// keygen.js
//
// Validate and/or generate keys specified by the filenames in the cfg object

var path = require('path');

try {
  var cfg = require('./config.json');
} catch(e){
  var cfg = {
    clientPub: './keys/clientPub.pem',
    clientPriv: './keys/clientPriv.pem',
    serverPub: './keys/serverPub.pem',
  };
};

require('./ensureKeys.js').ensureKeys(cfg, function(err){
  if(err){ throw err };
});
