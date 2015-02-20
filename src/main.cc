#include <node.h>
#include <nan.h>
#include <openssl/obj_mac.h>

#include "eckey.h"

using namespace v8;

void InitCurves(Handle<Object> exports) {
	Local<Object> obj = NanNew<Object>();
	obj->Set(NanNew<String>("secp112r1"), NanNew<Number>(NID_secp112r1));
	obj->Set(NanNew<String>("secp112r2"), NanNew<Number>(NID_secp112r2));
	obj->Set(NanNew<String>("secp128r1"), NanNew<Number>(NID_secp128r1));
	obj->Set(NanNew<String>("secp128r2"), NanNew<Number>(NID_secp128r2));
	obj->Set(NanNew<String>("secp160k1"), NanNew<Number>(NID_secp160k1));
	obj->Set(NanNew<String>("secp160r1"), NanNew<Number>(NID_secp160r1));
	obj->Set(NanNew<String>("secp160r2"), NanNew<Number>(NID_secp160r2));
	obj->Set(NanNew<String>("secp192r1"), NanNew<Number>(NID_X9_62_prime192v1));
	obj->Set(NanNew<String>("secp192k1"), NanNew<Number>(NID_secp192k1));
	obj->Set(NanNew<String>("secp224k1"), NanNew<Number>(NID_secp224k1));
	obj->Set(NanNew<String>("secp224r1"), NanNew<Number>(NID_secp224r1));
	obj->Set(NanNew<String>("secp256r1"), NanNew<Number>(NID_X9_62_prime256v1));
	obj->Set(NanNew<String>("secp256k1"), NanNew<Number>(NID_secp256k1));
	obj->Set(NanNew<String>("secp384r1"), NanNew<Number>(NID_secp384r1));
	obj->Set(NanNew<String>("secp521r1"), NanNew<Number>(NID_secp521r1));
	obj->Set(NanNew<String>("sect113r1"), NanNew<Number>(NID_sect113r1));
	obj->Set(NanNew<String>("sect113r2"), NanNew<Number>(NID_sect113r2));
	obj->Set(NanNew<String>("sect131r1"), NanNew<Number>(NID_sect131r1));
	obj->Set(NanNew<String>("sect131r2"), NanNew<Number>(NID_sect131r2));
	obj->Set(NanNew<String>("sect163k1"), NanNew<Number>(NID_sect163k1));
	obj->Set(NanNew<String>("sect163r1"), NanNew<Number>(NID_sect163r1));
	obj->Set(NanNew<String>("sect163r2"), NanNew<Number>(NID_sect163r2));
	obj->Set(NanNew<String>("sect193r1"), NanNew<Number>(NID_sect193r1));
	obj->Set(NanNew<String>("sect193r2"), NanNew<Number>(NID_sect193r2));
	obj->Set(NanNew<String>("sect233k1"), NanNew<Number>(NID_sect233k1));
	obj->Set(NanNew<String>("sect233r1"), NanNew<Number>(NID_sect233r1));
	obj->Set(NanNew<String>("sect239k1"), NanNew<Number>(NID_sect239k1));
	obj->Set(NanNew<String>("sect283k1"), NanNew<Number>(NID_sect283k1));
	obj->Set(NanNew<String>("sect283r1"), NanNew<Number>(NID_sect283r1));
	obj->Set(NanNew<String>("sect409k1"), NanNew<Number>(NID_sect409k1));
	obj->Set(NanNew<String>("sect409r1"), NanNew<Number>(NID_sect409r1));
	obj->Set(NanNew<String>("sect571k1"), NanNew<Number>(NID_sect571k1));
	obj->Set(NanNew<String>("sect571r1"), NanNew<Number>(NID_sect571r1));

	// Intimidated? Can't go wrong with NIST recommended curves

	obj->Set(NanNew<String>("nistp192"), NanNew<Number>(NID_X9_62_prime192v1));
	obj->Set(NanNew<String>("nistp224"), NanNew<Number>(NID_secp224r1));
	obj->Set(NanNew<String>("nistp256"), NanNew<Number>(NID_X9_62_prime256v1));
	obj->Set(NanNew<String>("nistp384"), NanNew<Number>(NID_secp384r1));
	obj->Set(NanNew<String>("nistp521"), NanNew<Number>(NID_secp521r1));

	exports->Set(NanNew<String>("ECCurves"), obj);
}

void InitModule(Handle<Object> exports) {
	ECKey::Init(exports);
	InitCurves(exports);
}

NODE_MODULE(native, InitModule)
