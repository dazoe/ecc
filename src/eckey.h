#ifndef ECC_ECKEY_H
#define ECC_ECKEY_H
#include <node.h>
#include <openssl/ec.h>

using namespace v8;
using namespace node;

class ECKey : public ObjectWrap {
	public:
		static void Init(Handle<Object> exports);

	private:
		ECKey(int curve);
		~ECKey();

		int mCurve;
		EC_KEY *mKey;
		bool mHasPrivateKey;

		// Node constructor
		static NAN_METHOD(New);

		// Node properties
		static NAN_GETTER(GetLastError);
		static NAN_GETTER(GetHasPrivateKey);
		static NAN_GETTER(GetPublicKey);
		static NAN_GETTER(GetPrivateKey);

		// Node methods
		static NAN_METHOD(Sign); // sign(digest)
		static NAN_METHOD(VerifySignature); // verifySignature(digest, signature)
		static NAN_METHOD(DeriveSharedSecret); // deriveSharedSecret(ECKey other)
};


#endif
