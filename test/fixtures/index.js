var ocsp = require('../../');

var fs = require('fs');
var rfc2560 = require('asn1.js-rfc2560');
var rfc5280 = require('asn1.js-rfc5280');
const { debug } = require('console');
var keyGen = require('selfsigned.js').create();
const util = require('util')


/*
   AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }
 */

exports.google = fs.readFileSync(__dirname + '/google-cert.pem');
exports.googleIssuer = fs.readFileSync(__dirname + '/google-issuer.pem');
exports.noExts = fs.readFileSync(__dirname + '/no-exts-cert.pem');

exports.certs = {};

[ 'issuer', 'good', 'revoked' ].forEach(function(name) {
  exports.certs[name] = {
    cert: fs.readFileSync(__dirname + '/' + name + '-cert.pem'),
    key: fs.readFileSync(__dirname + '/' + name + '-key.pem')
  };
});

exports.getOCSPCert = function getOCSPCert(options, cb) {
  console.debug("getOCSPCert start")
  if (!options)
    options = {};

  var size = options.size || 256;
  var commonName = options.commonName || 'local.host';
  var OCSPEndPoint = options.OCSPEndPoint || 'http://127.0.0.1:8000/ocsp';
  var extensions = options.extensions

  console.debug(util.inspect(extensions, {showHidden: false, depth: null, colors: true}))

  var issuer = options.issuer;
  if (issuer)
    issuer = ocsp.utils.toDER(issuer, 'CERTIFICATE');
  if (issuer)
    issuer = rfc5280.Certificate.decode(issuer, 'der');

  var issuerKeyData = options.issuerKey;

  if (issuerKeyData)
    issuerKeyData = ocsp.utils.toDER(options.issuerKey, 'RSA PRIVATE KEY');

  if (issuerKeyData)
    issuerKeyData = ocsp.utils.RSAPrivateKey.decode(issuerKeyData, 'der');
  else
    issuerKeyData = options.issuerKeyData;

  console.debug("getOCSPCert getPrime")
  function getPrime(cb) {
    keyGen.getPrime(size >> 1, function(err, prime) {
      if (err)
        return getPrime(cb);

      cb(prime);
    });
  }

  function getTwoPrimes(cb) {
    var primes = [];
    getPrime(done);
    getPrime(done);

    function done(prime) {
      primes.push(prime);
      if (primes.length === 2)
        return cb(primes[0], primes[1]);
    }
  }

  function getKeyData(cb) {
    getTwoPrimes(function(p, q) {
      var keyData = keyGen.getKeyData(p, q);
      if (!keyData)
        return getKeyData(cb);

      cb(keyData);
    });
  }
  console.debug("getOCSPCert getKeyData")
  getKeyData(function(keyData) {
    console.debug("serial: " + options.serial)
    console.debug("extensions: " + options.extensions)
    var certData = keyGen.getCertData({
      serial: options.serial,
      keyData: keyData,
      commonName: commonName,
      issuer: issuer,
      issuerKeyData: issuerKeyData,
      extensions: extensions
    });
    console.debug("getOCSPCert getCert")
    var pem = keyGen.getCert(certData, 'pem');
    return cb(pem, keyGen.getPrivate(keyData, 'pem'));
  });
};
