#include <node.h>
#include <nan.h>
#include <openssl/obj_mac.h>

#include "eckey.h"

using namespace v8;

void InitCurves(Handle<Object> exports) {
	Local<Object> obj = Object::New();
	obj->Set(NanNew<String>("secp112r1"), Number::New(NID_secp112r1));
	obj->Set(NanNew<String>("secp112r2"), Number::New(NID_secp112r2));
	obj->Set(NanNew<String>("secp128r1"), Number::New(NID_secp128r1));
	obj->Set(NanNew<String>("secp128r2"), Number::New(NID_secp128r2));
	obj->Set(NanNew<String>("secp160k1"), Number::New(NID_secp160k1));
	obj->Set(NanNew<String>("secp160r1"), Number::New(NID_secp160r1));
	obj->Set(NanNew<String>("secp160r2"), Number::New(NID_secp160r2));
	obj->Set(NanNew<String>("secp192r1"), Number::New(NID_X9_62_prime192v1));
	obj->Set(NanNew<String>("secp192k1"), Number::New(NID_secp192k1));
	obj->Set(NanNew<String>("secp224k1"), Number::New(NID_secp224k1));
	obj->Set(NanNew<String>("secp224r1"), Number::New(NID_secp224r1));
	obj->Set(NanNew<String>("secp256r1"), Number::New(NID_X9_62_prime256v1));
	obj->Set(NanNew<String>("secp256k1"), Number::New(NID_secp256k1));
	obj->Set(NanNew<String>("secp384r1"), Number::New(NID_secp384r1));
	obj->Set(NanNew<String>("secp521r1"), Number::New(NID_secp521r1));
	obj->Set(NanNew<String>("sect113r1"), Number::New(NID_sect113r1));
	obj->Set(NanNew<String>("sect113r2"), Number::New(NID_sect113r2));
	obj->Set(NanNew<String>("sect131r1"), Number::New(NID_sect131r1));
	obj->Set(NanNew<String>("sect131r2"), Number::New(NID_sect131r2));
	obj->Set(NanNew<String>("sect163k1"), Number::New(NID_sect163k1));
	obj->Set(NanNew<String>("sect163r1"), Number::New(NID_sect163r1));
	obj->Set(NanNew<String>("sect163r2"), Number::New(NID_sect163r2));
	obj->Set(NanNew<String>("sect193r1"), Number::New(NID_sect193r1));
	obj->Set(NanNew<String>("sect193r2"), Number::New(NID_sect193r2));
	obj->Set(NanNew<String>("sect233k1"), Number::New(NID_sect233k1));
	obj->Set(NanNew<String>("sect233r1"), Number::New(NID_sect233r1));
	obj->Set(NanNew<String>("sect239k1"), Number::New(NID_sect239k1));
	obj->Set(NanNew<String>("sect283k1"), Number::New(NID_sect283k1));
	obj->Set(NanNew<String>("sect283r1"), Number::New(NID_sect283r1));
	obj->Set(NanNew<String>("sect409k1"), Number::New(NID_sect409k1));
	obj->Set(NanNew<String>("sect409r1"), Number::New(NID_sect409r1));
	obj->Set(NanNew<String>("sect571k1"), Number::New(NID_sect571k1));
	obj->Set(NanNew<String>("sect571r1"), Number::New(NID_sect571r1));

	// Intimidated? Can't go wrong with NIST recommended curves

	obj->Set(NanNew<String>("nistp192"), Number::New(NID_X9_62_prime192v1));
	obj->Set(NanNew<String>("nistp224"), Number::New(NID_secp224r1));
	obj->Set(NanNew<String>("nistp256"), Number::New(NID_X9_62_prime256v1));
	obj->Set(NanNew<String>("nistp384"), Number::New(NID_secp384r1));
	obj->Set(NanNew<String>("nistp521"), Number::New(NID_secp521r1));

	exports->Set(NanNew<String>("ECCurves"), obj);
}

void InitModule(Handle<Object> exports) {
	ECKey::Init(exports);
	InitCurves(exports);
}

NODE_MODULE(native, InitModule)
