cmd_Release/obj.target/encrypter.node := flock ./Release/linker.lock g++ -shared -pthread -rdynamic -m64  -Wl,-soname=encrypter.node -o Release/obj.target/encrypter.node -Wl,--start-group Release/obj.target/encrypter/encrypter.o -Wl,--end-group 