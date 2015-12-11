#include <node.h>
#include <nan.h>
#include <openssl/obj_mac.h>

#include "eckey.h"

using namespace v8;

void InitCurves(Handle<Object> exports) {
	Local<Object> obj = Nan::New<Object>();
	obj->Set(Nan::New<String>("secp112r1").ToLocalChecked(), Nan::New<Number>(NID_secp112r1));
	obj->Set(Nan::New<String>("secp112r2").ToLocalChecked(), Nan::New<Number>(NID_secp112r2));
	obj->Set(Nan::New<String>("secp128r1").ToLocalChecked(), Nan::New<Number>(NID_secp128r1));
	obj->Set(Nan::New<String>("secp128r2").ToLocalChecked(), Nan::New<Number>(NID_secp128r2));
	obj->Set(Nan::New<String>("secp160k1").ToLocalChecked(), Nan::New<Number>(NID_secp160k1));
	obj->Set(Nan::New<String>("secp160r1").ToLocalChecked(), Nan::New<Number>(NID_secp160r1));
	obj->Set(Nan::New<String>("secp160r2").ToLocalChecked(), Nan::New<Number>(NID_secp160r2));
	obj->Set(Nan::New<String>("secp192r1").ToLocalChecked(), Nan::New<Number>(NID_X9_62_prime192v1));
	obj->Set(Nan::New<String>("secp192k1").ToLocalChecked(), Nan::New<Number>(NID_secp192k1));
	obj->Set(Nan::New<String>("secp224k1").ToLocalChecked(), Nan::New<Number>(NID_secp224k1));
	obj->Set(Nan::New<String>("secp224r1").ToLocalChecked(), Nan::New<Number>(NID_secp224r1));
	obj->Set(Nan::New<String>("secp256r1").ToLocalChecked(), Nan::New<Number>(NID_X9_62_prime256v1));
	obj->Set(Nan::New<String>("secp256k1").ToLocalChecked(), Nan::New<Number>(NID_secp256k1));
	obj->Set(Nan::New<String>("secp384r1").ToLocalChecked(), Nan::New<Number>(NID_secp384r1));
	obj->Set(Nan::New<String>("secp521r1").ToLocalChecked(), Nan::New<Number>(NID_secp521r1));
	obj->Set(Nan::New<String>("sect113r1").ToLocalChecked(), Nan::New<Number>(NID_sect113r1));
	obj->Set(Nan::New<String>("sect113r2").ToLocalChecked(), Nan::New<Number>(NID_sect113r2));
	obj->Set(Nan::New<String>("sect131r1").ToLocalChecked(), Nan::New<Number>(NID_sect131r1));
	obj->Set(Nan::New<String>("sect131r2").ToLocalChecked(), Nan::New<Number>(NID_sect131r2));
	obj->Set(Nan::New<String>("sect163k1").ToLocalChecked(), Nan::New<Number>(NID_sect163k1));
	obj->Set(Nan::New<String>("sect163r1").ToLocalChecked(), Nan::New<Number>(NID_sect163r1));
	obj->Set(Nan::New<String>("sect163r2").ToLocalChecked(), Nan::New<Number>(NID_sect163r2));
	obj->Set(Nan::New<String>("sect193r1").ToLocalChecked(), Nan::New<Number>(NID_sect193r1));
	obj->Set(Nan::New<String>("sect193r2").ToLocalChecked(), Nan::New<Number>(NID_sect193r2));
	obj->Set(Nan::New<String>("sect233k1").ToLocalChecked(), Nan::New<Number>(NID_sect233k1));
	obj->Set(Nan::New<String>("sect233r1").ToLocalChecked(), Nan::New<Number>(NID_sect233r1));
	obj->Set(Nan::New<String>("sect239k1").ToLocalChecked(), Nan::New<Number>(NID_sect239k1));
	obj->Set(Nan::New<String>("sect283k1").ToLocalChecked(), Nan::New<Number>(NID_sect283k1));
	obj->Set(Nan::New<String>("sect283r1").ToLocalChecked(), Nan::New<Number>(NID_sect283r1));
	obj->Set(Nan::New<String>("sect409k1").ToLocalChecked(), Nan::New<Number>(NID_sect409k1));
	obj->Set(Nan::New<String>("sect409r1").ToLocalChecked(), Nan::New<Number>(NID_sect409r1));
	obj->Set(Nan::New<String>("sect571k1").ToLocalChecked(), Nan::New<Number>(NID_sect571k1));
	obj->Set(Nan::New<String>("sect571r1").ToLocalChecked(), Nan::New<Number>(NID_sect571r1));

	// Intimidated? Can't go wrong with NIST recommended curves

	obj->Set(Nan::New<String>("nistp192").ToLocalChecked(), Nan::New<Number>(NID_X9_62_prime192v1));
	obj->Set(Nan::New<String>("nistp224").ToLocalChecked(), Nan::New<Number>(NID_secp224r1));
	obj->Set(Nan::New<String>("nistp256").ToLocalChecked(), Nan::New<Number>(NID_X9_62_prime256v1));
	obj->Set(Nan::New<String>("nistp384").ToLocalChecked(), Nan::New<Number>(NID_secp384r1));
	obj->Set(Nan::New<String>("nistp521").ToLocalChecked(), Nan::New<Number>(NID_secp521r1));

	exports->Set(Nan::New<String>("ECCurves").ToLocalChecked(), obj);
}

void InitModule(Handle<Object> exports) {
	ECKey::Init(exports);
	InitCurves(exports);
}

NODE_MODULE(native, InitModule)
