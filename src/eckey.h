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
		static Handle<Value> GetLastError(Local<String> property, const AccessorInfo &info);
		static Handle<Value> GetHasPrivateKey(Local<String> property, const AccessorInfo &info);
		static Handle<Value> GetPublicKey(Local<String> property, const AccessorInfo &info);
		static Handle<Value> GetPrivateKey(Local<String> property, const AccessorInfo &info);

		// Node methods
		static NAN_METHOD(Sign); // sign(digest)
		static NAN_METHOD(VerifySignature); // verifySignature(digest, signature)
		static NAN_METHOD(DeriveSharedSecret); // deriveSharedSecret(ECKey other)
};


#endif
