var encrypter = require('./build/Release/encrypter');

var input = "This is a string input";

encrypter.asyncencrypt(input, function(err, result) {
    console.warn(result);
});
