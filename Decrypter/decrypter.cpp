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

Handle<Value> AsyncDecrypt(const Arguments& args);
void AsyncWork(uv_work_t* req);
void AsyncAfter(uv_work_t* req);


// information about the asynchronous decrypting.
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
Handle<Value> AsyncDecrypt(const Arguments& args) {
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

    // convert it to string
    std::string rawInput = baton->input; 
 
    // Setting misc. data
	int keylength = 128; //Key length is 128 to be JAVA-compatible (only 128 or 192 or 256!)

	// Getting the key from the input string
	std::string hexKeyHead = rawInput.substr(0, 8);
	std::reverse(hexKeyHead.begin(), hexKeyHead.end());
	std::string hexKeyTail = rawInput.substr(rawInput.size()-24, 24);
	std::reverse(hexKeyTail.begin(), hexKeyTail.end());
	std::string hexKey = hexKeyHead + hexKeyTail;
//	/*DEBUG*/ std::cout << "DECRYPT: key in HEX:\t" << hexKey << std::endl;

	// Getting the data from the input string
    std::string hexData = rawInput.substr(8, rawInput.size()-32); // the bug was 24 instead of 32

    // To check decrypting the C++ crypted data
    // TODO: Last 16 bytes fail (it seems that only encrypting is a problem)
//    /*TEMP*/ hexData = "09CDD2D21BC0D8C1C640F3D545A90D43523482FCA86B89DBCD6D25C86DD87E81";
//    /*TEMP*/ std::transform(hexData.begin(), hexData.end(), hexData.begin(), ::tolower);
//    /*DEBUG*/ std::cout << "DECRYPT: input data in HEX:\t" << hexData << std::endl;

    // Manipulating the key
	unsigned char AESKey[keylength/8];
	memset(AESKey, 0, keylength/8); // initialize to (unsigned char)zero
	std::string charKey = hexToString(hexKey); // HARDCODED to chars
//	/*DEBUG*/ std::cout << "DECRYPT: charKey:\t" << charKey << std::endl;
	for (size_t i=0; i<charKey.size(); i++)
		memset(AESKey+i, charKey.at(i), 1); // HARDCODED to hex bytes
//	/*DEBUG*/ std::cout << "DECRYPT: HEX KEY:\t";
//	/*DEBUG*/ hex_print(AESKey, sizeof(AESKey));

	// Manipulating the input data
	std::string charData = hexToString(hexData); // from hex to char
	// next line has a bug, since extracted data is padded according to AES_BLOCK_SIZE
	// which means it contains padded length, not real length
	// TODO: try to remove extra padding (via parameter to the function or?)
	size_t inputslength = hexData.size()/2; // the size of the input (but padded)
	// (since 2 hex bytes represent one input char)

	/* generate input with a given length */
	unsigned char aesInput[inputslength]; // creating the container for the encrypted data
	for (size_t i=0; i<charData.size(); i++)
		memset(aesInput+i, int(charData.at(i)), 1); // filling the memory
//	/*DEBUG*/ std::cout << "DECRYPT: Input:\t";
//	/*DEBUG*/ hex_print(aesInput, sizeof(aesInput));
//	/*DEBUG*/ std::cout << "DECRYPT: Input length:\t" << inputslength << std::endl;

	// Creating the IV
//	/*TEMP*/ unsigned char tempIV[AES_BLOCK_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	memcpy(iv, AESKey, AES_BLOCK_SIZE); // IV is first AES_BLOCK_SIZE (16) bytes of key

	// Preparing the output container
	// added -1 or otherwise it pads 32 bytes to 48 TODO: It helps here, but encrypt maybe not
//	const size_t encslength = ((inputslength - 1 + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
//	/*DEBUG*/ std::cout << "DECRYPT: encslength:\t" << encslength << std::endl;
	unsigned char output[inputslength];
	memset(output, 0, sizeof(output));

	// =============================================
	// This is an OLD version
	// Hard to extract data (weird padding at the end)
	// Causes problems to remove padding (if string
	// is a multiple of AES_BLOCK_SIZE
	// Decrypting
//	AES_KEY key;
//	AES_set_decrypt_key(AESKey, keylength, &key);
//	/*TEMP*/ int tempLength;
//	AES_cbc_encrypt(aesInput, output, encslength /*tempLength*/, &key, iv, AES_DECRYPT);

	// =============================================
	// EVP wrapped decrypt (original version sent)
	// Reserve space for output
	int length, finalLength = 0;

	// Decrypt the string data
	EVP_CIPHER_CTX *encryptHandle = new EVP_CIPHER_CTX;
	EVP_CIPHER_CTX_init(encryptHandle);
	EVP_DecryptInit_ex(encryptHandle, EVP_aes_128_cbc(), NULL, AESKey, iv);
	EVP_DecryptUpdate(encryptHandle, output, &length, aesInput, sizeof(aesInput));
	finalLength += length;
	EVP_DecryptFinal_ex(encryptHandle, output + length, &length);
	finalLength += length;

	// Convert the output into a string
	std::string outputArtifact((char*) output, finalLength);
	// =============================================

//	// Debug output
//	/*DEBUG*/ std::cout << "DECRYPT: Decrypt:\t";
//	/*DEBUG*/ hex_print(output, sizeof(output));
//	/*DEBUG*/ std::cout << std::endl;
//	/*DEBUG*/ std::cout << "DECRYPT: Decrypt text:\t" << outputArtifact << std::endl; //TEMP ADDED

	// Release memory
	EVP_CIPHER_CTX_cleanup(encryptHandle);
	delete encryptHandle;
//	/*DEBUG*/ std::cout << "ENCRYPT: output artifact\t" << outputArtifact << std::endl;

    // convert it to string and store it to baton
    baton->result = outputArtifact.c_str();
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
    target->Set(String::NewSymbol("asyncdecrypt"),
        FunctionTemplate::New(AsyncDecrypt)->GetFunction());
}

NODE_MODULE(decrypter, RegisterModule);
