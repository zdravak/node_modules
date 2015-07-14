#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <stdlib.h>
#include <node.h>

#include "boost/uuid/random_generator.hpp"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_io.hpp"

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

#include "cryptor.h"

using namespace v8;

Handle<Value> AsyncEncrypt(const Arguments& args);
void AsyncWork(uv_work_t* req);
void AsyncAfter(uv_work_t* req);


// information about the asynchronous encrypting.
struct Baton {
    Persistent<Function> callback;

    bool error;
    std::string error_message;

    // Custom data that can be passed through.
    std::string input; // input string passed from JS
    std::string result; // output string container
};

// This is the function called directly from JS. It creates a
// work request object and schedules it for execution.
Handle<Value> AsyncEncrypt(const Arguments& args) {
    HandleScope scope;

    if (!args[1]->IsFunction()) {
        return ThrowException(Exception::TypeError(
            String::New("Second argument must be a callback function")));
    }
    // Cast argument 2 to a function.
    Local<Function> callback = Local<Function>::Cast(args[1]);

    // The baton holds custom status information for this asynchronous call,
    // like the callback function called when returning to the main
    // thread and the status information.
    Baton* baton = new Baton();
    baton->error = false;
    baton->callback = Persistent<Function>::New(callback); // instatiation
    
    // get the input string from JS
    v8::String::Utf8Value rawJSInput(args[0]->ToString());

    // convert it to string and storing it to the baton
    baton->input = std::string(*rawJSInput);
       
    // This creates the work request struct.
    uv_work_t *req = new uv_work_t();
    req->data = baton;

    // Schedule work request with libuv. Here the functions
    // that should be executed in the threadpool and back in the main thread
    // after the threadpool function completed can be specified.
    int status = uv_queue_work(uv_default_loop(), req, AsyncWork,
                               (uv_after_work_cb)AsyncAfter);
    assert(status == 0);

    return Undefined();
}

// The main function (for actual encrypting) is executed in another thread
// at some point after it has been scheduled.
// IT MUST NOT USE ANY V8 FUNCTIONALITY. Otherwise an extension will crash
// randomly. If parameters passed into the original call are to be used,
// they have to be converted to PODs or some other fancy method.
void AsyncWork(uv_work_t* req) {
    Baton* baton = static_cast<Baton*>(req->data);
    
    ////////////////////////
    // START OF THE MAIN JOB
    // Setting misc. data
	int keylength = 128; //Key length is 128 to be JAVA-compatible (only 128 or 192 or 256!)
	size_t inputslength = baton->input.size(); // the size of the input

	// Generating the UUID key
	std::string stringKey = uuidKey(); // string key for ciphering and to append it to the crypted load

    // Manipulating the key
	unsigned char AESKey[keylength/8];
	memset(AESKey, 0, keylength/8); // initialize to (unsigned char)zero
	std::string charKey = hexToString(stringKey); // HARDCODED to chars
//	/*DEBUG*/ std::cout << "ENCRYPT: charKey:\t" << charKey << std::endl;
//	/*DEBUG*/ std::cout << "ENCRYPT: KeyBytes:\t";
	for (size_t i=0; i<charKey.size(); i++)
	{
//		/*DEBUG*/ std::cout << " " << int(charKey.at(i));
		memset(AESKey+i, charKey.at(i), 1); // HARDCODED to hex bytes
	}

	/* generate input with a given length */
	unsigned char aesInput[inputslength]; // creating the container for the input data
//	/*DEBUG*/ std::cout << "ENCRYPT: InputBytes:\t";
	for (size_t i=0; i<baton->input.size(); i++)
	{
//		/*DEBUG*/ std::cout << " " << int(input.at(i));
		memset(aesInput+i, baton->input.at(i), 1); // filling the memory
	}

	// Creating the IV
//	/*TEMP*/ unsigned char tempIV[AES_BLOCK_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	memcpy(iv, AESKey, AES_BLOCK_SIZE); // IV is first AES_BLOCK_SIZE (16) bytes of key
//	/*DEBUG*/ std::cout << "ENCRYPT: IV:\t\t";
//	/*DEBUG*/ hex_print(iv, sizeof(iv));

	// Preparing the output container
	// Round up input size to AES_BLOCK_SIZE multiple
	// added -1 or otherwise it pads 32 bytes to 48 TODO: Bug?
	const size_t encslength = ((inputslength - 1 + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
//	/*DEBUG*/ std::cout << "ENCRYPT: EncodedString length:\t" << encslength << std::endl;
	unsigned char output[encslength]; // create output container
	memset(output, 0, sizeof(output)); // initialize output to unsigned char(0)

	// =============================================
	// EVP wrapped encrypt (original version sent)
	int length, finalLength = 0;
	EVP_CIPHER_CTX *encryptHandle = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(encryptHandle);
	EVP_EncryptInit_ex(encryptHandle, EVP_aes_128_cbc(), NULL, AESKey , iv);
	EVP_EncryptUpdate(encryptHandle, output, &length, aesInput, inputslength);
	finalLength += length;
	EVP_EncryptFinal_ex(encryptHandle, output + length, &length);
	finalLength += length;

	// Convert the data into a string
	std::string stringCryptedData((char*) output, finalLength);

	// EVP AES cleanup
	EVP_CIPHER_CTX_cleanup(encryptHandle);
	delete encryptHandle;

	// Create output artifacts
	std::string hexCryptedData = stringToHex(stringCryptedData);
	std::string head = stringKey.substr(0, 8);
	std::string tail = stringKey.substr(8, stringKey.size());
	std::reverse(head.begin(), head.end());
	std::reverse(tail.begin(), tail.end());

	// Output atrifact
	std::string outputArtifact = head + hexCryptedData + tail;
//	/*DEBUG*/ std::cout << "ENCRYPT: output artifact\t" << outputArtifact << std::endl;

    // convert it to string and store it to baton
    baton->result = outputArtifact;
	////////////////

    // If the work fails, the baton->error_message should be set to
    // the error string and baton->error to true.
}

// This function is executed in the main V8/JavaScript thread. It's
// safe to use V8 functions again. Use HandleScope!
void AsyncAfter(uv_work_t* req) {
    HandleScope scope;
    Baton* baton = static_cast<Baton*>(req->data);

    if (baton->error) {
        Local<Value> err = Exception::Error(String::New(baton->error_message.c_str()));

        // Preparing the parameters for the callback function.
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };

        TryCatch try_catch;
        baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    } else {
        const unsigned argc = 2;
        Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(String::New(baton->result.c_str()))
        };

        TryCatch try_catch;
        baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    }

    // The callback is a permanent handle, disposing of it manually.
    baton->callback.Dispose();

    // The baton and the work_req struct are created with new, so they have to
    // be manually removed.
    delete baton;
    delete req;
}

void RegisterModule(Handle<Object> target) {
    target->Set(String::NewSymbol("asyncencrypt"),
        FunctionTemplate::New(AsyncEncrypt)->GetFunction());
}

NODE_MODULE(encrypter, RegisterModule);
