/// !doc
/// 
/// # X509 signature builder
/// 
/// `var x509 = require('js509').x509`
/// 
import * as asn1 from './asn1';
import { types } from './asn1';
import { OIDS } from './oids';

/// * `sign = x509.buildSignature(cert, hash, signature)`  
///   Builds a signature from a certificate, a hash and a signature computed on the hash.  
///   The `cert`, `hash` and `signature` parameters must be passed as buffers.  
///   `cert` must be in X509 DER (binary) format.  
///   Returns the signature object in X509 DER (binary) format, as a Buffer 
export function buildSignature(cert: Buffer, hash: Buffer, signature: Buffer) {
	var certNode = asn1.fromBuffer(cert);
	var serial = certNode.children[0].children[1];
	var issuer = certNode.children[0].children[3];

	var root = asn1.createNode(types.SEQ);
	root.add(types.OID, OIDS.pkcs7.signedData);
	var signedData = root.addEoc(types.SEQ);
	// version
	signedData.addInt(1);
	// digestAlgorithms
	signedData.addSet().addSeqOid(OIDS.oiwsecsig.sha1);
	// contentInfo
	signedData.addSeqOid(OIDS.pkcs7.data, types.BYTES, hash);
	// certificates
	signedData.addEoc(certNode);
	// crls (TODO)
	// signerInfos
	var signerInfo = signedData.addSet().addSeq();
	// version
	signerInfo.addInt(1);
	// issuer and serial number
	var issuerAndSerial = signerInfo.addSeq();
	issuerAndSerial.add(issuer);
	issuerAndSerial.add(serial);
	// digest algorithm
	signerInfo.addSeqOid(OIDS.oiwsecsig.sha1);
	// authenticated attributes (none)
	// encryption algorithm
	signerInfo.addSeqOid(OIDS.pkcs1.rsa);
	// encrypted digest (signature)
	signerInfo.add(types.BYTES, signature);
	// unatthenticatd attributes (none)
	return asn1.toBuffer(root);
}

/// * `len = x509.guessSignatureSize(cert)`  
///   Returns an estimated size for a signature for certifcate `cert`.  
///   The returned length is always an overestimation. The caller may use it to 
///   reserve an area where the signature will be copied later.
export function guessSignatureSize(cert: Buffer) {
	// sha1 hash is 20 bytes and rsa signature is 128 bytes (key = 1k)
	// quad them to be on the safe side
	return buildSignature(cert, new Buffer(4 * 20), new Buffer(4 * 128)).length;
};