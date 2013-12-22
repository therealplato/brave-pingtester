// Test the request/response signing with the BRAVE Collective Core Service

var braveEC = require('brave-ec');
var request = require('request');

try {
  var cfg = require('./config.json');
} catch(e){
  var cfg = {
    serverRoot: 'http://localhost:8080',
    appName: 'node-pingtester',
    appId: '52937b80c9ba583635dd1466',
    clientPub: './keys/clientPub.pem',
    clientPriv: './keys/clientPriv.pem',
    serverPub: './keys/serverPub.pem',
  };
};
braveEC.cfg(cfg); // for the module to remember this state info

require('./ensureKeys.js').ensureKeys(cfg, function(err){
  if(err){ throw err };
  braveEC.loadPemPrivFromFile(cfg.clientPriv, function(err, keys){
    if(err){ throw err; };
    var hex = keys.pub.hex;
    console.log('hex.length', hex.length);
    if(hex.match(/^00/) && hex.length == 132){ // 66 bytes padded
      hex = hex.slice(4); // remove leading two bytes to get 64 bit key
    }
    console.log('Your hex public key is \n'+hex);
    init(cfg, keys);
  });
});

function init(cfg, keys){
  var body = "";
  date = new Date().toUTCString();
  braveEC.sign(date, cfg.serverRoot+'/api/ping', body, function(err, sig){
    if(err){ console.log('Signature error: '+err) }
    else { 
      console.log('Ping signature:', sig);
      console.log('Sig length:', sig.length);
    };
    send(date, cfg.serverRoot+'/api/ping', body, sig, function(err, res, body){
      if(err){ console.log('Request error: '+err) }
      console.log(res.headers);
      console.log(res.statusCode);
      console.log(res.request.headers);
      console.log(res.request.body);
      //console.log(body);
    });
  });
};

function send(date, uri, body, sig, callback){
  var options = {
    url: uri,
    headers: {
      'Date': date,
      'User-Agent': 'node-pingtester',
      'X-Service': cfg.appId,
      'X-Signature': sig,
    },
    body: body,
  };
  request(options, function(err, res, body){
    if(err){ return callback(err) };
      //braveEC.validate(, 
    callback(null, res, body);
  });
}
