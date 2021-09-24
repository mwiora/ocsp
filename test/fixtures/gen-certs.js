#!/usr/bin/env node

var fs = require('fs');
var fixtures = require('.');
var rfc2560 = require('asn1.js-rfc2560');
var rfc5280 = require('asn1.js-rfc5280');

var crypto = require('crypto');

var OCSPEndPoint = 'http://127.0.0.1:8000/ocsp';

console.debug("getOCSPCert setAIA")
var ext = rfc5280.AuthorityInfoAccessSyntax.encode([ {
  accessMethod: rfc2560['id-pkix-ocsp'],
  accessLocation: {
    type: 'uniformResourceIdentifier',
    value: OCSPEndPoint
  }
} ], 'der');

var extensionsCA = rfc5280.KeyUsage.encode({
  unused: 0,
  data: 6
  }, 'der');

var extensionsLEAF = rfc5280.KeyUsage.encode({
  unused: 0,
  data: 32+128
  }, 'der');

var options = {
  serial: 42,
  commonName: 'mega.ca',
  size: 2048,
  extensions: [ {
    extnID: [1, 3, 6, 1, 5, 5, 7, 1, 1],
    critical: false,
    extnValue: ext
  },
  {
    extnID: [2, 5, 29, 15],
    critical: true,
    extnValue: extensionsCA
  }
]
};

fixtures.getOCSPCert(options, function(cert, key) {
  console.debug("gen issuer")
  fs.writeFileSync(__dirname + '/issuer-cert.pem', cert);
  fs.writeFileSync(__dirname + '/issuer-key.pem', key);

  var options = {
    issuer: cert,
    issuerKey: key,
    serial: 43,
    size: 2048,
    extensions: [ {
      extnID: [1, 3, 6, 1, 5, 5, 7, 1, 1],
      critical: false,
      extnValue: ext
    },
    {
      extnID: [2, 5, 29, 15],
      critical: true,
      extnValue: extensionsLEAF
    }
  ]
  };

  fixtures.getOCSPCert(options, function(cert, key) {
    fs.writeFileSync(__dirname + '/good-cert.pem', cert);
    fs.writeFileSync(__dirname + '/good-key.pem', key);

    options.serial++;
    fixtures.getOCSPCert(options, function(cert, key) {
      fs.writeFileSync(__dirname + '/revoked-cert.pem', cert);
      fs.writeFileSync(__dirname + '/revoked-key.pem', key);
    });
  });
});
