"use strict";

/// !doc
/// 
/// Functions and classes for handling certificates and private keys
///
var locale = require("streamline-locale");
var asn1 = require("./asn1");
var types = asn1.types;
var OIDS = require("./oids").OIDS;
var crypto = require('crypto');
var util = require('util');

/// ## Verify integrity of certificate, private key, passphrase, CA certificates
///  When CA certificates are given, find out whether one of them signs the given certificate
///  result is object with attributes: 
///  - key: decrypted private key (if available)
///  - cert: certificate object
///  - error: error string if error has occurred
exports.integrity = function(certificate, key, passphrase, cacerts) {
	var result = {};
	// remove encryption of key
	if (certificate) {
		try {
			var cert = new Certificate(certificate);
			result.cert = cert;
		} catch (e) {
			return {
				error: ((e instanceof Error) ? e.message : "" + e)
			};
		}
	}
	if (key) {
		try {
			var decrypted = exports.stripEncryption(key, passphrase, true);
		} catch (e) {
			return {
				error: ((e instanceof Error) ? e.message : "" + e)
			};
		}
		result.key = decrypted;
		if (certificate) {
			// sign and verify
			var testBuffer = new Buffer("abcdefghijklmnopqrstuvwxyz");
			var sign = crypto.createSign("RSA-SHA1");
			sign.update(testBuffer);
			try {
				var signature = sign.sign(decrypted);
			} catch (e) {
				console.error(e);
				return {
					error: locale.format(module, "errorSign", e)
				};
			}
			var verify = crypto.createVerify("RSA-SHA1");
			verify.update(testBuffer);
			try {
				if (!verify.verify(certificate, signature)) return {
					error: locale.format(module, "wrongKey")
				};
			} catch (e) {
				console.error(e);
				return {
					error: locale.format(module, "errorVerify", e)
				};
			}
		}
	}
	if (cacerts && cacerts.length) {
		var err = null;
		for (var i = 0; i < cacerts.length; i++) {
			try {
				if (cert.verify(cacerts[i])) return result;
			} catch (e) {
				// tracer && tracer("Error in some CA certificate: "+e)
				err = err || e;
			}
		}
		if (err) {
			return {
				error: locale.format(module, "errorCA", err)
			};
		} else {
			return {
				error: locale.format(module, "noCA")
			};
		}
	}
	// OK
	return result;
};

/// ## Strip the encryption from a private key
///    `stripEncryption(key, passphrase, test)`
///   Arguments are a private key in PEM format and the passphrase. The output will be the private key without encryption in PEM format.
///   When the private key has not been encrypted, the passphrase will be ignored and the private key will be returned unchanged.
///   If the optional 3rd parameter `test` is set, the function parses the resulting private key to check whether it has the correct format (ASN.1).
///
exports.stripEncryption = function(key, passphrase, test) {
	var r = /^-----BEGIN ((?:RSA )*PRIVATE KEY)-----\s+(?:Proc-Type: ([\w,]+)\s+DEK-Info: ([\-\w]+)(?:,(\w+))?)?(?:([\w\=\/\+\s]+))/.exec(key);
	if (r) {
		// remove spaces 
		if (r[2] === '4,ENCRYPTED') {
			if (!passphrase) throw new Error(locale.format(module, "missingPassphrase"));
			if (r[4]) {
				var iv = new Buffer(r[4], "hex");
				passphrase = passphrase || "";
				var keyLength = 24;
				switch (r[3]) {
					case 'DES-EDE3-CBC':
						keyLength = 24;
						break;
					case 'DES-CBC':
						keyLength = 8;
						break;
					default:
						throw new Error("Wrong cipher");
				}
				var ds = "";
				while (ds.length < keyLength) {
					var hash = crypto.createHash('md5');
					hash.update(ds, 'binary');
					hash.update(passphrase, 'binary');
					hash.update(iv);
					var dig = hash.digest();
					if (Buffer.isBuffer(dig)) {
						ds += dig.toString('binary');
					} else {
						ds += dig;
					}
				}
				var keypass = new Buffer(ds.substr(0, keyLength), 'binary');
				var cipher = crypto.createDecipheriv(r[3], keypass, iv);
			} else {
				throw new Error("Wrong private key format: missing salt");
			}
			var buffer = new Buffer(r[5].replace(/\s+/g, ""), "base64");
			try {
				var b1 = cipher.update(buffer, null, 'binary');
				var b2 = cipher.final('binary');
			} catch (e) {
				// node 0.10 throws TypeError on wrong passphrase but node 0.10 throw regular error so we test its message.
				if (e instanceof TypeError || /^error:06065064:/.test(e.message)) throw new Error(locale.format(module, "wrongPass"));
				throw new Error(locale.format(module, "errorDecrypt", e));
			}
			buffer = new Buffer(b1 + b2, 'binary');
			if (test) {
				try {
					asn1.fromBuffer(buffer);
				} catch (e) {
					throw new Error(locale.format(module, "wrongFormat"));
				}
			}
			key = expandToPem(buffer, r[1]);
		}
		return key;
	} else throw new Error(locale.format(module, "noPEM"));
};

function _getDn(info) {
	var result = "C=" + info.countryName + (info.stateOrProvinceName ? ", ST=" + info.stateOrProvinceName : "") + (info.localityName ? ", L=" + info.localityName : "") + ", O=" + info.organizationName + ", ";
	info.organizationalUnitNames.forEach(function(ou) {
		result += "OU=" + ou + ", ";
	});
	return result + "CN=" + info.commonName;
}

function oidStrings(set, oid) {
	var oidNode = asn1.createNode(types.OID, oid);
	return set.children.filter(function(n) {
		return n.children[0].children[0].equals(oidNode);
	}).map(function(n) {
		var vnode = n.children[0].children[1];
		return vnode.buf.slice(vnode.pos, vnode.pos + vnode.len).toString("utf8");
	});
}

/// # X509 certificate class
/// 
/// * `cert = new Certificate(buf)`  
///   Creates a new certificate object from an X509 buffer or a PEM content
class Certificate {
	constructor(buffer) {
		if (!Buffer.isBuffer(buffer)) {
			// assume PEM content
			var startIndex = buffer.indexOf('-----BEGIN CERTIFICATE-----');
			var endIndex = buffer.indexOf('-----END CERTIFICATE-----');
			if (startIndex < 0 || endIndex < 0) throw new Error(locale.format(module, "certNoPEM"));
			var b64 = buffer.substring(startIndex + 27, endIndex);
			buffer = new Buffer(b64, "base64");
		}
		this.parsed = asn1.fromBuffer(buffer);
		var type = this.parsed.children[0].children[0].type;
		// for certificates of version 1, the version field is not counted
		this.shift = (type === asn1.types.INTEGER) ? 0 : 1;
	}
	/// * `str = cert.toString()`  
	///   Returns the contents of the certificate in tree form
	toString() {
		return this.parsed.toString();
	}
	/// * `subject = cert.subject`  
	///   Returns the subject information (see source for list of fields returned);
	get subject() {
		var node = this.parsed.children[0].children[this.shift + 4];
		return {
			countryName: oidStrings(node, OIDS.at.countryName)[0],
			stateOrProvinceName: oidStrings(node, OIDS.at.stateOrProvinceName)[0],
			localityName: oidStrings(node, OIDS.at.localityName)[0],
			organizationName: oidStrings(node, OIDS.at.organizationName)[0],
			organizationalUnitNames: oidStrings(node, OIDS.at.organizationalUnitName),
			commonName: oidStrings(node, OIDS.at.commonName)[0],
		};
	}
	/// * `subjectDn = cert.subjectDn`
	///   Returns the distinguished name of the subject information in a single string
	get subjectDn() {
		return _getDn(this.subject);
	}
	// make distinguished name out of data in object
	/// * `issuer = cert.issuer`  
	///   Returns the issuer information (see source for list of fields returned);
	get issuer() {
		var node = this.parsed.children[0].children[this.shift + 2];
		return {
			countryName: oidStrings(node, OIDS.at.countryName)[0],
			stateOrProvinceName: oidStrings(node, OIDS.at.stateOrProvinceName)[0],
			localityName: oidStrings(node, OIDS.at.localityName)[0],
			organizationName: oidStrings(node, OIDS.at.organizationName)[0],
			organizationalUnitNames: oidStrings(node, OIDS.at.organizationalUnitName),
			commonName: oidStrings(node, OIDS.at.commonName)[0],
		};
	}
	/// * `issuerDn = cert.issuerDn`
	///   Returns the distinguished name of the subject information in a single string
	get issuerDn() {
		return _getDn(this.issuer);
	}
	/// * `notAfter = cert.notAfter`  
	///   Returns the expiry time (number of milliseconds after 1 Jan 1970). The result can be used directly 
	///   as argument for the constructor of a Date object 
	get notAfter() {
		var node = this.parsed.children[0].children[this.shift + 3];
		return node.children[1].getMillis();
	}
	/// * `notBefore = cert.notBefore`  
	///   Returns the time at which the certificate will start to be valid (number of milliseconds after 1 Jan 1970).  
	///   The result can be used directly as argument for the constructor of a Date object 
	get notBefore() {
		var node = this.parsed.children[0].children[this.shift + 3];
		return node.children[0].getMillis();
	}
	/// * `publicKey = cert.publicKey`  
	///   Returns a buffer with the public key of the certificate  
	get publicKey() {
		var node = this.parsed.children[0].children[this.shift + 5];
		return node.children[1].getData();
	}
	/// * `verify(certificate)`
	///   Verifies the signature of this certificate against the public key of the certificate 
	///   as given in the parameter (certificate object or string with PEM format)
	///   Result is true, when the verification is successful.
	verify(certificate) {
		var tbs = this.parsed.children[0];
		var tbsbuffer = asn1.toBuffer(tbs);
		var algorithm = this.parsed.children[1].children[0];
		var name;
		if (algorithm.type === asn1.types.OID) {
			var cont = algorithm.getData().toString("binary");
			switch (cont) {
				case OIDS.pkcs1.sha1Rsa.toString("binary"):
					name = "RSA-SHA1";
					break;
				case OIDS.pkcs1.sha256Rsa.toString("binary"):
					name = "RSA-SHA256";
					break;
				case OIDS.pkcs1.sha384Rsa.toString("binary"):
					name = "RSA-SHA384";
					break;
				case OIDS.pkcs1.sha512Rsa.toString("binary"):
					name = "RSA-SHA512";
					break;
				case OIDS.pkcs1.sha224Rsa.toString("binary"):
					name = "RSA-SHA224";
					break;
				default:
					throw new Error(locale.format(module, "unsupportedAlg"));
			}
			var verify = crypto.createVerify(name);
			verify.update(tbsbuffer);
			if (certificate instanceof Certificate) {
				certificate = expandToPem(asn1.toBuffer(certificate.parsed), "CERTIFICATE");
			}
			if (!verify.verify(certificate, this.parsed.children[2].getData())) {
				throw new Error(locale.format(module, "nonVerify"));
			}
			return true;
		} else throw new Error(locale.format(module, "noOID"));
	}
}
exports.Certificate = Certificate;

// Expands a buffer with DER encoded data to the corresponding PEM format. The name of the resulting 
// type (e. g. CERTIFICATE, RSA PRIVATE KEY) must be given in the second parameter 
function expandToPem(buffer, name) {
	var result = "-----BEGIN " + name + "-----\n";
	var text = buffer.toString("base64");
	var i;
	for (i = 0; i < text.length - 64; i += 64) // insert line breaks in base64 
		result += text.substr(i, 64) + '\n';
	result += text.substr(i) + '\n-----END ' + name + '-----\n';
	return result;
}