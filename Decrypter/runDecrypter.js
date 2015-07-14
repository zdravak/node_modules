var decrypter = require('./build/Release/decrypter');

var input = "4c9880e7e51ce6027b94cbe8626940906a70551dae50f34e17526f9452ce492188942add4ee4bbd15fb1d72861748fc4";

decrypter.asyncdecrypt(input, function(err, result) {
    console.warn(result);
});
