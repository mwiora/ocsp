'use strict';

var ocsp = require('../ocsp');

var http = require('http');
var https = require('https');
var util = require('util');
var crypto = require('crypto');
var pino = require('pino');

var async = require('async');
var rfc2560 = require('asn1.js-rfc2560');
var rfc5280 = require('asn1.js-rfc5280');
const { exit } = require('process');

const logger = pino({
  level: 'debug',
  prettyPrint: {
    colorize: true,
    translateTime: true
  }
});

var certdb;

function Server(options) {
  http.Server.call(this, this.handler);
  this.options = options;
  logger.level = options.configobj.loglevel;

  certdb = this.options.configobj.certdb;
  this.key = this.options.configobj.issuerkeydata;
  this.cert = rfc5280.Certificate.decode(
      ocsp.utils.toDER(options.configobj.issuercertdata, 'CERTIFICATE'),
      'der');
  this.cert = this.cert.tbsCertificate;

  var issuerName = rfc5280.Name.encode(this.cert.subject, 'der');
  logger.info(`Issuer of The CA:` + this.cert.subject.value[0][0].value)
  var issuerKey = this.cert.subjectPublicKeyInfo.subjectPublicKey.data;

  this.certID = {};
  Object.keys(ocsp.utils.digestRev).forEach(function(digest) {
    this.certID[digest] = {
      issuerNameHash: crypto.createHash(digest).update(issuerName).digest(),
      issuerKeyHash: crypto.createHash(digest).update(issuerKey).digest()
    };
  }, this);

  this.certs = {};
}
util.inherits(Server, http.Server);
module.exports = Server;

Server.create = function create(options) {
  return new Server(options);
};

Server.prototype.addCert = function addCert(serial, status, info) {
  this.certs[serial.toString(16)] = {
    type: status,
    value: info
  };
};

Server.prototype.handler = function handler(req, res) {
  logger.trace(JSON.stringify(req.headers,null,2));

  logger.debug('Request source ' + res.connection.remoteAddress);

  var chunks = [];
  var body;

  var self = this;
  if (req.method == 'GET') {
    logger.info('Request type is GET');

    logger.trace(util.inspect(req));

    switch (req.url) {
      case "/root":
        if(typeof this.options.configobj.rootcertdata !== 'undefined' && this.options.configobj.rootcertdata !== ''){
          res.writeHead(200);
          // Writing string data
          res.write(this.options.configobj.rootcertdata, 'utf8', () => {
            logger.debug('Returning root to client for request: ' + req.url);
          });
          res.end();
        } else {
          res.writeHead(200);
          res.write('no root cert available');
          logger.debug('Reporting no root to client for request: ' + req.url);
          res.end();
        }  
        return;
      case "/intermediate":
        res.writeHead(200);
        // Writing string data
        res.write(this.options.configobj.issuercertdata, 'utf8', () => {
          logger.debug('Returning intermediate to client for request: ' + req.url);
        });
        res.end();
        return;
      default:
        logger.debug('Request content original ' + req.url);
        var decoded = decodeURIComponent(req.url);
        logger.trace("URI Decoded: " + decoded);
        var subdecoded = decoded.substring(1);
        logger.trace("Substring: " + subdecoded);

        chunks.push(Buffer.from(subdecoded, 'base64'));
        body = Buffer.concat(chunks);
        processData(body);
    }
  }

  if (req.method == 'POST') {
    logger.info('Request type is POST');
    logger.debug(JSON.stringify(req.headers));

    if (req.headers['content-type'] !== 'application/ocsp-request') {
      logger.info('Request was not of type application/ocsp-request - abort');
      return res.writeHead(400);
    }
    
    req.on('readable', function() {
      var chunk = req.read();
      if (chunk)
        chunks.push(chunk);
    });

    req.on('end', function() {
      logger.info("POST request finished");
      body = Buffer.concat(chunks);
      processData(body);
    });
  }

  function processData(body) {
    var ocspReq;
     try {
       logger.debug("Trying to decode request");
       ocspReq = rfc2560.OCSPRequest.decode(body, 'der');
       logger.trace("decoded: " + util.inspect(ocspReq));
     } catch (e) {
       logger.warn("Malformed request");
       return done(errRes('malformed_request'));
     }
 
    logger.trace(JSON.stringify(ocspReq,null,2));
    self.getResponses(ocspReq, function(err, responses) {
      // Assume not found
      if (err) {
        logger.error(err)
        res.writeHead(404);
        res.end();
        return;
      }
 
      return done(responses);
    });
   }
 
   function done(out) {
     res.writeHead(200, {
       'Content-Type': 'application/ocsp-response',
       'Content-Length': out.length
     });
     res.end(out);
   }
 
   function errRes(status) {
     return rfc2560.OCSPResponse.encode({
       responseStatus: status
     }, 'der');
   }
 
}

Server.prototype.getResponses = function getResponses(req, cb) {
  var self = this;

  var reqList = req.tbsRequest.requestList;

  // TODO(indutny): support signed requests
  async.map(reqList, function(req, cb) {
    self.getResponse(req, cb);
  }, function(err, responses) {
    if (err)
      return cb(err);

    // TODO(indutny): send extensions
    var basic = {
      tbsResponseData: {
        version: 'v1',
        responderID: {
          type: 'byKey',
          value: self.certID.sha1.issuerKeyHash
        },
        producedAt: new Date(),
        responses: responses
      },

      signatureAlgorithm: {
        algorithm: ocsp.utils.signRev.sha512WithRSAEncryption
      },
      signature: null

      // TODO(indutny): send certs?
    };

    var sign = crypto.createSign('sha512WithRSAEncryption');
    sign.update(rfc2560.ResponseData.encode(basic.tbsResponseData, 'der'));
    basic.signature = {
      unused: 0,
      data: sign.sign(self.key)
    };

    var res = {
      responseStatus: 'successful',
      responseBytes: {
        responseType: 'id-pkix-ocsp-basic',
        response: rfc2560.BasicOCSPResponse.encode(basic, 'der')
      }
    };

    cb(null, rfc2560.OCSPResponse.encode(res, 'der'));
  });
};

Server.prototype.getResponse = function getResponse(req, cb) {
  var certID = req.reqCert;
  
  var digestId = certID.hashAlgorithm.algorithm.join('.');
  var digest = ocsp.utils.digest[digestId];
  if (!digest)
  logger.error('Unknown digest: ' + digestId);
  
  var expectedID = this.certID[digest];
  if (!expectedID) {
    return cb(new Error('Unknown digest: ' + digestId));
  }

  if (expectedID.issuerNameHash.toString('hex') !==
  certID.issuerNameHash.toString('hex')) {
    return cb(new Error('Issuer name mismatch - unkown signing CA'));
  }
  
  if (expectedID.issuerKeyHash.toString('hex') !==
  certID.issuerKeyHash.toString('hex')) {
    return cb(new Error('Issuer key mismatch - unkown signing CA'));
  }
  
  var serial = certID.serialNumber.toString(16);
  logger.info(`Request Certificate Serial: ` + serial)

  if(certdb == "memory") {
    var response = {
      certId: certID,
      certStatus: null,
      thisUpdate: new Date(),
      nextUpdate: new Date(+new Date() + 24 * 3600 * 1e3)
    };

    logger.debug(`CERTDB is memory - looking for cert in memory`)
    var cert = this.certs[serial];
    if (cert) {
      response.certStatus = cert;
    } else {
      response.certStatus = {
        type: 'unknown',
        value: null
      };
    }    
    logger.debug(`Serial (hex): ` + serial + ` Status: ` + JSON.stringify(response.certStatus))
    cb(null, response);
  }

  if(certdb.includes("https://")) {
    async.map([serial], call, function(err, data) {
      logger.debug(`CERTDB contains https - looking for cert in remote https directory`)
      logger.trace(data);
      var certStatus = {
        type: null,
        value: null
      }

      var response = {
        certId: certID,
        certStatus: certStatus,
        thisUpdate: new Date(),
        nextUpdate: new Date(+new Date() + 24 * 3600 * 1e3),
      }; 
  
      if (data[0] === '') {
        response.certStatus.type = 'unknown';
      } else {
        var status = JSON.parse(data[0]).Status;
        switch (status) {
          case 'Valid': {
            logger.info("Returning status GOOD");
            response.certStatus.type = 'good';
            break;
          };
          case 'Revoked': {
            logger.info("Returning status REVOKED");
            response.certStatus.type = 'revoked';
            response.certStatus.value = { 
              revocationTime: Date.parse(JSON.parse(data[0]).RevokedAt),
              revocationReason: JSON.parse(data[0]).Reason
            }
            break;
          };
          default: {
            logger.info("Returning status UNKOWN");
            response.certStatus.type = 'unknown';
          }
        }
      }
      logger.trace("Returning: " + JSON.stringify(response,null, 2));
      cb(null, response);  

    });
  }  

  function call(serial, cb) {
  
    const options = {
      timeout: 3000,
      rejectUnauthorized: false
    }
    var url = certdb + serial;
    logger.info("Starting call against Pebble " + url);
    let req = https.get(url, options);

    req.on("error", (err) => {
      logger.error("Error: " + err.message);
      cb(null, '');
    });

    req.on('response', (resp) => {
      let data = '';

      // A chunk of data has been received.
      resp.on('data', (chunk) => {
        data += chunk;
      });

      // The whole response has been received. Print out the result.
      resp.on('end', () => {
        cb(null, data);
      });
    });

  }

};