cmd_Release/decrypter.node := ln -f "Release/obj.target/decrypter.node" "Release/decrypter.node" 2>/dev/null || (rm -rf "Release/decrypter.node" && cp -af "Release/obj.target/decrypter.node" "Release/decrypter.node")
