// ensureKeys.js
// Given a config file or default config, look for three PEM files
// Warn if serverPub missing, generate priv/pub files if clientPriv missing
// Test the request/response signing with the BRAVE Collective Core Service

var crypto = require('crypto');
var http = require('http');
var path = require('path');
var fs = require('fs');
var braveEC = require('brave-ec');
var async = require('async');

//var request = require('request');
//var jws = require('jws')



function ensureKeys(cfg, callback){
  testKeys(function(err, keysOK){
    if(err){ return callback(err); };
    if(keysOK.serverPub === 'notfound'){
      console.log('Error, the server public key for your application was not found at '+cfg.serverPub, ', download it from '+cfg.serverRoot+'/application/manage/'+cfg.appId);
    } else if(keysOK.serverPub === false){
      console.log('Error, the server public key does not appear to be a PEM encoded public key for the NIST prime256v1 curve. Download the PEM public key from '+cfg.serverRoot+'/application/manage/'+cfg.appId);
    };

    if(keysOK.clientPriv === 'notfound'){
      console.log('Client private key not found at '+cfg.clientPriv);
      console.log('Generating a new keypair'); 
      braveEC.genKeypair(function(err, keys){
        if(err){ return callback(err) };

        var pemPriv = keys.priv.pem;
        var privFilename = path.normalize(process.cwd()+'/'+cfg.clientPriv);
        console.log('Saving private key as '+privFilename);
        fs.writeFileSync(privFilename, pemPriv
        ,{ 
          encoding:'utf8', 
          mode: parseInt("400", 8), // set mode user read only
        });

        var pemPub = keys.pub.pem;
        var pubFilename = path.normalize(process.cwd()+'/'+cfg.clientPub);
        console.log('Saving public key as '+pubFilename);
        fs.writeFileSync(pubFilename, pemPub
        ,{
          encoding:'utf8', 
          mode: parseInt("400", 8), // set mode user read only
        });
      });
      // braveEC.loadPemPrivFromStdin(function(err, keys){ });
    } else if(keysOK.clientPriv === false){
      return callback(new Error('Private key '+cfg.clientPriv+' doesn\'t look like a valid key'));
    } else if(keysOK.clientPriv === true){
      if(keysOK.clientPub === 'notfound'){
        console.log('Private key found without public key.');
        var privFilename = path.normalize(process.cwd()+'/'+cfg.clientPriv);
        var pubFilename = path.normalize(process.cwd()+'/'+cfg.clientPub);
        var pemPriv = fs.readFileSync(privFilename, {encoding: 'utf8'});
        braveEC._genPubKey(pemPriv, function(err, pemPub){
          if(err){ return callback(err); }
          console.log('Saving public key as '+pubFilename);
          fs.writeFileSync(pubFilename, pemPub, {encoding: 'utf8'});
        });
        return callback(null);
      } else if(keysOK.clientPub === 'false'){
        return callback('Invalid public key found.');
      } else {
        console.log(JSON.stringify(keysOK, null, 2));
        return callback(null);
      }
    } else {
      console.log(JSON.stringify(keysOK, null, 2));
      return callback('Weird keysOK');
    };
  });

  function testKeys(callback){
    var keyStatus = {
      clientPub: null, 
      clientPriv: null, 
      serverPub: null, 
    };

    async.series(
  [ 
    function(done){
      if(fs.existsSync(cfg.clientPriv)){  
        braveEC.loadPemPrivFromFile(cfg.clientPriv, function(err, result){
          if(err){ 
            keyStatus.clientPriv = false;
          } else {
            keyStatus.clientPriv = true;
          };
          done(null);
        });
      } else {
        keyStatus.clientPriv = 'notfound';
        done(null);
      };
    },
    function(done){
      if(fs.existsSync(cfg.clientPub)){
        braveEC.loadPemPubFromFile(cfg.clientPub, function(err, result){
          if(err){ 
            keyStatus.clientPub = false;
          } else {
            keyStatus.clientPub = true;
          };
          done(null);
        });
      } else {
        keyStatus.clientPub = 'notfound';
        done(null);
      };
    },
    function(done){
      if(fs.existsSync(cfg.serverPub)){
        braveEC.loadPemPubFromFile(cfg.serverPub, function(err, result){
          if(err){ 
            console.log(err);
            keyStatus.serverPub = false;
          } else {
            keyStatus.serverPub = true;
          };
          done(null);
        });
      } else {
        keyStatus.serverPub = 'notfound';
        done(null);
      };
    }
  ],
    function(err, results){
      callback(err, keyStatus);
    });
  };
};


module.exports = {
  ensureKeys: ensureKeys,
};

/*
function(cfg){
  var defaultCfg = {
    serverRoot: 'http://localhost:8080',
    appName: 'node-pingtester',
    appId: '52937b80c9ba583635dd1466',
    clientPub: './keys/clientPub.pem',
    clientPriv: './keys/clientPriv.pem',
    serverPub: './keys/serverPub.pem',
  };

  if(cfg === undefined || cfg === null){
    try{
      cfg = require('./config.json');
    } catch(e){
      cfg = defaultCfg;
    };
  };
  ensureKeys(cfg, function(err){
    if(err){ throw err };
  });
};
*/
