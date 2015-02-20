#include <string.h>
#include <node.h>
#include <nan.h>
#include <node_buffer.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>

#include "eckey.h"

using namespace v8;
using namespace node;


// Not sure where this came from. but looks like a function that should be part of openssl
int static inline EC_KEY_regenerate_key(EC_KEY *eckey, const BIGNUM *priv_key) {
	if (!eckey) return 0;
	int ok = 0;
	BN_CTX *ctx = NULL;
	EC_POINT *pub_key = NULL;
	const EC_GROUP *group = EC_KEY_get0_group(eckey);
	if ((ctx = BN_CTX_new()) == NULL)
		goto err;
	pub_key = EC_POINT_new(group);
	if (pub_key == NULL)
		goto err;
	if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;
	EC_KEY_set_private_key(eckey, priv_key);
	EC_KEY_set_public_key(eckey, pub_key);
	ok = 1;
err:
	if (pub_key)
		EC_POINT_free(pub_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);
	return ok;
}

ECKey::ECKey(int curve) {
	mHasPrivateKey = false;
	mCurve = curve;
	mKey = EC_KEY_new_by_curve_name(mCurve);
	if (!mKey) {
		NanThrowError("EC_KEY_new_by_curve_name Invalid curve?");
		return;
	}
}
ECKey::~ECKey() {
	if (mKey) {
		EC_KEY_free(mKey);
	}
}

// Node module init
void ECKey::Init(Handle<Object> exports) {
	Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
	tpl->SetClassName(NanNew<String>("ECKey"));
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	//Accessors
	tpl->InstanceTemplate()->SetAccessor(NanNew<String>("HasPrivateKey"), GetHasPrivateKey);
	tpl->InstanceTemplate()->SetAccessor(NanNew<String>("PublicKey"), GetPublicKey);
	tpl->InstanceTemplate()->SetAccessor(NanNew<String>("PrivateKey"), GetPrivateKey);

	//Methods (Prototype)
	tpl->PrototypeTemplate()->Set(NanNew<String>("sign"), NanNew<FunctionTemplate>(Sign)->GetFunction());
	tpl->PrototypeTemplate()->Set(NanNew<String>("verifySignature"), NanNew<FunctionTemplate>(VerifySignature)->GetFunction());
	tpl->PrototypeTemplate()->Set(NanNew<String>("deriveSharedSecret"), NanNew<FunctionTemplate>(DeriveSharedSecret)->GetFunction());

	Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
	exports->Set(NanNew<String>("ECKey"), constructor);
}

// Node constructor function
// new ECKey(curve, buffer, isPublic)
NAN_METHOD(ECKey::New) {
	if (!args.IsConstructCall()) {
		return NanThrowError("Must use new keyword");
	}
	if (args[0]->IsUndefined()) {
		return NanThrowError("First argument must be an ECCurve");
	}
	NanScope();
	ECKey *eckey = new ECKey(args[0]->NumberValue());
	if (!args[1]->IsUndefined()) {
		if (!Buffer::HasInstance(args[1])) {
			return NanThrowError("Second parameter must be a buffer");
		}
		//we have a second parameter, check the third to see if it is public or private.
		Handle<Object> buffer = args[1]->ToObject();
		const unsigned char *bufferData = (unsigned char *) Buffer::Data(buffer);
		if ((args[2]->IsUndefined()) || (args[2]->BooleanValue() == false)) {
			// it's a private key
			BIGNUM *bn = BN_bin2bn(bufferData, Buffer::Length(buffer), BN_new());
			if (EC_KEY_regenerate_key(eckey->mKey, bn) == 0) {
				BN_clear_free(bn);
				return NanThrowError("Invalid private key");
			}
			BN_clear_free(bn);
			eckey->mHasPrivateKey = true;
		} else {
			// it's a public key
			if (!o2i_ECPublicKey(&(eckey->mKey), &bufferData, Buffer::Length(buffer))) {
				return NanThrowError("o2i_ECPublicKey failed, Invalid public key");
			}
		}
	} else {
		if (!EC_KEY_generate_key(eckey->mKey)) {
			return NanThrowError("EC_KEY_generate_key failed");
		}
		eckey->mHasPrivateKey = true;
	}
	eckey->Wrap(args.Holder());
	NanReturnHolder();
}

static void FreeBufferData(char *data, void *hint) {
	free(data);
}

// Node properity functions
NAN_GETTER(ECKey::GetHasPrivateKey) {
	NanScope();
	ECKey *eckey = ObjectWrap::Unwrap<ECKey>(args.Holder());
	NanReturnValue(NanNew<Boolean>(eckey->mHasPrivateKey));
}
NAN_GETTER(ECKey::GetPublicKey) {
	ECKey *eckey = ObjectWrap::Unwrap<ECKey>(args.Holder());
	const EC_GROUP *group = EC_KEY_get0_group(eckey->mKey);
	const EC_POINT *point = EC_KEY_get0_public_key(eckey->mKey);
	unsigned int nReq = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
	if (!nReq) {
		return NanThrowError("EC_POINT_point2oct error");
	}
	unsigned char *buf, *buf2;
	buf = buf2 = (unsigned char *)malloc(nReq);
	if (EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, buf, nReq, NULL) != nReq) {
		return NanThrowError("EC_POINT_point2oct didn't return correct size");
	}
	NanScope();
	NanReturnValue(NanNewBufferHandle((char *)buf2, nReq, FreeBufferData, NULL));
}
NAN_GETTER(ECKey::GetPrivateKey) {
	ECKey *eckey = ObjectWrap::Unwrap<ECKey>(args.Holder());
	const BIGNUM *bn = EC_KEY_get0_private_key(eckey->mKey);
	if (bn == NULL) {
		return NanThrowError("EC_KEY_get0_private_key failed");
	}
	int priv_size = BN_num_bytes(bn);
	unsigned char *priv_buf = (unsigned char *)malloc(priv_size);
	int n = BN_bn2bin(bn, priv_buf);
	if (n != priv_size) {
		return NanThrowError("BN_bn2bin didn't return priv_size");
	}
	NanScope();
	NanReturnValue(NanNewBufferHandle((char *)priv_buf, priv_size, FreeBufferData, NULL));
}

// Node method functions
NAN_METHOD(ECKey::Sign) {
	NanScope();
	ECKey * eckey = ObjectWrap::Unwrap<ECKey>(args.Holder());
	if (!Buffer::HasInstance(args[0])) {
		return NanThrowError("digest must be a buffer");
	}
	if (!eckey->mHasPrivateKey) {
		return NanThrowError("cannot sign without private key");
	}
	Handle<Object> digest = args[0]->ToObject();
	const unsigned char *digest_data = (unsigned char *)Buffer::Data(digest);
	unsigned int digest_len = Buffer::Length(digest);

	ECDSA_SIG *sig = ECDSA_do_sign(digest_data, digest_len, eckey->mKey);
	if (!sig) {
		return NanThrowError("ECDSA_do_sign");
	}
	int sig_len = i2d_ECDSA_SIG(sig, NULL);
	if (!sig_len) {
		return NanThrowError("i2d_ECDSA_SIG");
	}
	unsigned char *sig_data, *sig_data2;
	sig_data = sig_data2 = (unsigned char *)malloc(sig_len);
	if (i2d_ECDSA_SIG(sig, &sig_data) != sig_len) {
		ECDSA_SIG_free(sig);
		free(sig_data2);
		return NanThrowError("i2d_ECDSA_SIG didnot return correct length");
	}
	ECDSA_SIG_free(sig);
	NanReturnValue(NanNewBufferHandle((char *)sig_data2, sig_len, FreeBufferData, NULL));
}
NAN_METHOD(ECKey::VerifySignature) {
	NanScope();
	ECKey *eckey = ObjectWrap::Unwrap<ECKey>(args.Holder());
	if (!Buffer::HasInstance(args[0])) {
		return NanThrowError("digest must be a buffer");
	}
	if (!Buffer::HasInstance(args[1])) {
		return NanThrowError("signature must be a buffer");
	}
	Handle<Object> digest = args[0]->ToObject();
	Handle<Object> signature = args[1]->ToObject();
	const unsigned char *digest_data = (unsigned char *)Buffer::Data(digest);
	const unsigned char *signature_data = (unsigned char *)Buffer::Data(signature);
	unsigned int digest_len = Buffer::Length(digest);
	unsigned int signature_len = Buffer::Length(signature);
	int result = ECDSA_verify(0, digest_data, digest_len, signature_data, signature_len, eckey->mKey);
	if (result == -1) {
		return NanThrowError("ECDSA_verify");
	} else if (result == 0) {
		NanReturnValue(NanNew<Boolean>(false));
	} else if (result == 1) {
		NanReturnValue(NanNew<Boolean>(true));
	} else {
		return NanThrowError("ECDSA_verify gave an unexpected return value");
	}
}
NAN_METHOD(ECKey::DeriveSharedSecret) {
	NanScope();
	if (args[0]->IsUndefined()) {
		return NanThrowError("other is required");
	}
	ECKey *eckey = ObjectWrap::Unwrap<ECKey>(args.Holder());
	ECKey *other = ObjectWrap::Unwrap<ECKey>(args[0]->ToObject());
	if (!other) {
		return NanThrowError("other must be an ECKey");
	}
	unsigned char *secret = (unsigned char*)malloc(512);
	int len = ECDH_compute_key(secret, 512, EC_KEY_get0_public_key(other->mKey), eckey->mKey, NULL);
	NanReturnValue(NanNewBufferHandle((char *)secret, len, FreeBufferData, NULL));
}
