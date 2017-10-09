"use strict";

/// !doc
/// 
/// Functions and classes for handling certificates and private keys
///
import { locale } from 'f-locale';
import * as asn1 from './asn1';
import { types, Node } from './asn1';
import { OIDS } from './oids';
import * as crypto from 'crypto';
debugger;
const resources = locale.resources(__filename);

/// ## Verify integrity of certificate, private key, passphrase, CA certificates
///  When CA certificates are given, find out whether one of them signs the given certificate
///  result is object with attributes: 
///  - key: decrypted private key (if available)
///  - cert: certificate object
///  - error: error string if error has occurred
export interface IntegrityResult {
	cert?: Certificate;
	key?: string;
	error?: string;
}
export function integrity(certificate: string, key: string, passphrase: string, cacerts: string[]): IntegrityResult {
	var result = {} as IntegrityResult;
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
			var decrypted = stripEncryption(key, passphrase, true);
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
					error: resources.format("errorSign", e)
				};
			}
			var verify = crypto.createVerify("RSA-SHA1");
			verify.update(testBuffer);
			try {
				if (!verify.verify(certificate, signature)) return {
					error: resources.format("wrongKey")
				};
			} catch (e) {
				console.error(e);
				return {
					error: resources.format("errorVerify", e)
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
				error: resources.format("errorCA", err)
			};
		} else {
			return {
				error: resources.format("noCA")
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
export function stripEncryption(key: string, passphrase: string, test?: boolean) {
	var r = /^-----BEGIN ((?:RSA )*PRIVATE KEY)-----\s+(?:Proc-Type: ([\w,]+)\s+DEK-Info: ([\-\w]+)(?:,(\w+))?)?(?:([\w\=\/\+\s]+))/.exec(key);
	if (r) {
		// remove spaces 
		if (r[2] === '4,ENCRYPTED') {
			if (!passphrase) throw new Error(resources.format("missingPassphrase"));
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
					// TODO: check if 'latin1' works, to eliminate cast
					hash.update(ds, 'binary' as any);
					hash.update(passphrase, 'binary' as any);
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
				if (e instanceof TypeError || /^error:06065064:/.test(e.message)) throw new Error(resources.format("wrongPass"));
				throw new Error(resources.format("errorDecrypt", e));
			}
			buffer = new Buffer(b1 + b2, 'binary');
			if (test) {
				try {
					asn1.fromBuffer(buffer);
				} catch (e) {
					throw new Error(resources.format("wrongFormat"));
				}
			}
			key = expandToPem(buffer, r[1]);
		}
		return key;
	} else throw new Error(resources.format("noPEM"));
};

// Convert object with parts of DN into string representation of DN.
// Parameters:
// info: object with countryName, stateOrProvinceName, localityName, organizationName, organizationalUnitNames, commonName
// rfc2253: output separated just with comma without blank, starting with CN.
export interface CertficateInfo {
	countryName: string;
	stateOrProvinceName: string;
	localityName: string;
	organizationName: string;
	organizationalUnitNames: string[];
	commonName: string;
}
function _getDn(info: CertficateInfo, rfc2253?: boolean) {

	function _escape(str: string) {
		return str.replace(/([ ,\+"\\<>;])/g, "\\$1");
	}
	var result: string[] = [];
	if (info.countryName) result.push("C=" + _escape(info.countryName));
	if (info.stateOrProvinceName) result.push("ST=" + _escape(info.stateOrProvinceName));
	if (info.localityName) result.push("L=" + _escape(info.localityName));
	if (info.organizationName) result.push("O=" + info.organizationName);
	info.organizationalUnitNames.forEach(function (ou) {
		result.push("OU=" + ou);
	});
	if (info.commonName) result.push("CN=" + info.commonName);
	if (rfc2253)
		return result.reverse().join(","); // without spaces
	else
		return result.join(", ");
}

function oidStrings(set: Node, oid: Buffer) {
	var oidNode = asn1.createNode(types.OID, oid);
	return set.children!.filter(function (n) {
		return n.children[0].children[0].equals(oidNode);
	}).map(function (n) {
		var vnode = n.children[0].children[1];
		return vnode.buf.slice(vnode.pos, vnode.pos + vnode.len).toString("utf8");
	});
}

/// # X509 certificate class
/// 
/// * `cert = new Certificate(buf)`  
///   Creates a new certificate object from an X509 buffer or a PEM content
export class Certificate {
	private parsed: Node;
	private shift: number;
	constructor(buffer: Buffer | string) {
		if (!Buffer.isBuffer(buffer)) {
			// assume PEM content
			var startIndex = buffer.indexOf('-----BEGIN CERTIFICATE-----');
			var endIndex = buffer.indexOf('-----END CERTIFICATE-----');
			if (startIndex < 0 || endIndex < 0) throw new Error(resources.format("certNoPEM"));
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
	get sigAlgorithmName() {
		var algorithm = this.parsed.children[1].children[0];
		if (algorithm.type === asn1.types.OID) {
			var cont = algorithm.getData().toString("binary");
			switch (cont) {
				case OIDS.pkcs1.sha1Rsa.toString("binary"):
					return "RSA-SHA1";
				case OIDS.pkcs1.sha256Rsa.toString("binary"):
					return "RSA-SHA256";
				case OIDS.pkcs1.sha384Rsa.toString("binary"):
					return "RSA-SHA384";
				case OIDS.pkcs1.sha512Rsa.toString("binary"):
					return "RSA-SHA512";
				case OIDS.pkcs1.sha224Rsa.toString("binary"):
					return "RSA-SHA224";
				default:
					throw new Error(resources.format("unsupportedAlg"));
			}
		} else {
			throw new Error(resources.format("noOID"));
		}
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
	///   Returns the distinguished name of the subject information in a single string in RFC2253 format
	///   starting with common name
	get subjectDnRFC2253() {
		return _getDn(this.subject, true);
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

	/// * `serial = cert.serial`
	///   Returns the certificate issuer serial number as a buffer
	get serial() {
		var node = this.parsed.children[0].children[this.shift];
		if (node.type === asn1.types.INTEGER)
			return node.getData();
		else
			throw new Error("Wrong type");
	}

	/// * `serialDecimal = cert.serialDecimal`
	///   Returns the certificate issuer serial number as a string in decimal representation
	get serialDecimal() {
		var serialParts = [0];
		var serial = this.serial;
		for (var i = 0; i < serial.length; i++) {
			var extra = +serial[i];
			var j = serialParts.length;
			while (--j >= 0) {
				const tmp = serialParts[j] * 256 + extra;
				extra = Math.floor(tmp / 1000000000);
				if (extra) serialParts[j] = tmp - extra * 1000000000;
				else serialParts[j] = tmp;
			}
			if (extra) serialParts.unshift(extra);
		}
		var serialResult = '' + serialParts[0];
		for (var i = 1; i < serialParts.length; i++) {
			const tmp = "00000000" + serialParts[i];
			serialResult += tmp.substr(tmp.length - 9);
		}
		return serialResult;
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
	/// * `publicKey = cert.publicKey`  
	///   Returns an object with the data of the public key of the certificate  
	get publicKeyDetails() {
		var node = this.parsed.children[0].children[this.shift + 5];
		var key = node.children[1].getData();
		var keytype = node.children[0].children[0];
		var o = asn1.fromBuffer(key);
		// at the moment, only RSA keys are supported
		if (keytype.type === asn1.types.OID && keytype.getData().toString("binary") === OIDS.pkcs1.rsa.toString("binary")) {
			var a = o.children[0].getData();
			var b = o.children[1].getData();
			return { modulus: a, exponent: b };
		}
		throw new Error("Wrong key type " + keytype.toString());
	}

	/// * `verify(certificate)`
	///   Verifies the signature of this certificate against the public key of the certificate 
	///   as given in the parameter (certificate object or string with PEM format)
	///   Result is true, when the verification is successful.
	verify(certificate: Certificate | string) {
		var tbs = this.parsed.children[0];
		var tbsbuffer = asn1.toBuffer(tbs);
		var name = this.sigAlgorithmName;
		var verify = crypto.createVerify(name);
		verify.update(tbsbuffer);
		if (certificate instanceof Certificate) {
			certificate = expandToPem(asn1.toBuffer(certificate.parsed), "CERTIFICATE");
		}
		if (!verify.verify(certificate, this.parsed.children[2].getData())) {
			throw new Error(resources.format("nonVerify"));
		}
		return true;
	}
}

// Expands a buffer with DER encoded data to the corresponding PEM format. The name of the resulting 
// type (e. g. CERTIFICATE, RSA PRIVATE KEY) must be given in the second parameter 
function expandToPem(buffer: Buffer, name: string) {
	var result = "-----BEGIN " + name + "-----\n";
	var text = buffer.toString("base64");
	var i;
	for (i = 0; i < text.length - 64; i += 64) // insert line breaks in base64 
		result += text.substr(i, 64) + '\n';
	result += text.substr(i) + '\n-----END ' + name + '-----\n';
	return result;
}