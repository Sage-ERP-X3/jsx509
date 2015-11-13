"use strict";

var toBuffer = exports.toBuffer = function(str) {
	var vals = str.split('.').map(function(s) {
		return parseInt(s, 10);
	});
	var bytes = [40 * vals[0] + vals[1]];
	vals.slice(2).forEach(function(val) {
		var i = bytes.length;
		while (val >= 128) {
			bytes.splice(i, 0, val % 128);
			val = Math.floor(val / 128);
		}
		bytes.splice(i, 0, val);
		for (; i < bytes.length - 1; i++) bytes[i] |= 0x80;
	});
	return new Buffer(bytes);
};

var fromBuffer = exports.fromBuffer = function(buf) {
	var vals = [Math.floor(buf[0] / 40), buf[0] % 40];
	var pos = 1;
	while (pos < buf.length) {
		var val = 0;
		do {
			val = val * 128 + (buf[pos] & 0x7f);
		} while (buf[pos++] & 0x80);
		vals.push(val);
	}
	if (pos !== buf.length) throw new Error("bad oid: " + buf.toString("hex"));
	return vals.join('.');
};

var OIDS = exports.OIDS = {
	x9algorithm: {
		dsa: toBuffer("1.2.840.10040.4.1"),
		dsaSha1: toBuffer("1.2.840.10040.4.3"),
	},
	pkcs1: {
		rsa: toBuffer("1.2.840.113549.1.1.1"),
		md2Rsa: toBuffer("1.2.840.113549.1.1.2"),
		md5Rsa: toBuffer("1.2.840.113549.1.1.4"),
		sha1Rsa: toBuffer("1.2.840.113549.1.1.5"),
		sha256Rsa: toBuffer("1.2.840.113549.1.1.11"),
		sha384Rsa: toBuffer("1.2.840.113549.1.1.12"),
		sha512Rsa: toBuffer("1.2.840.113549.1.1.13"),
		sha224Rsa: toBuffer("1.2.840.113549.1.1.14"),
	},
	pkcs2: {
		md2: toBuffer("1.2.840.113549.2.2"),
		md5: toBuffer("1.2.840.113549.2.5"),
	},
	pkcs7: {
		data: toBuffer("1.2.840.113549.1.7.1"),
		signedData: toBuffer("1.2.840.113549.1.7.2"),
		envelopedData: toBuffer("1.2.840.113549.1.7.3"),
		signedAndEnvelopedData: toBuffer("1.2.840.113549.1.7.4"),
		digestedData: toBuffer("1.2.840.113549.1.7.5"),
		encryptedData: toBuffer("1.2.840.113549.1.7.6"),
	},
	pkcs9: {
		email: toBuffer("1.2.840.113549.1.9.1"),
		contentType: toBuffer("1.2.840.113549.1.9.3"),
		messageDigest: toBuffer("1.2.840.113549.1.9.4"),
		signingTime: toBuffer("1.2.840.113549.1.9.5"),
		adbeRevocation: toBuffer("1.2.840.113583.1.1.8"),
	},
	oiwsecsig: {
		sha1: toBuffer("1.3.14.3.2.26"),
	},
	teletrust: {
		ripmd160: toBuffer("1.3.36.3.2.1"),
		ripmd128: toBuffer("1.3.36.3.2.2"),
		ripmd256: toBuffer("1.3.36.3.2.3"),
		ripmd160Rsa: toBuffer("1.3.36.3.3.1.2"),
		ripmd128Rsa: toBuffer("1.3.36.3.3.1.3"),
		ripmd256Rsa: toBuffer("1.3.36.3.3.1.4"),
	},
	nist: {
		sha256: toBuffer("2.16.840.1.101.3.4.2.1"),
		sha384: toBuffer("2.16.840.1.101.3.4.2.2"),
		sha512: toBuffer("2.16.840.1.101.3.4.2.3"),
		sha224: toBuffer("2.16.840.1.101.3.4.2.4"),
		sha224Dsa: toBuffer("2.16.840.1.101.3.4.3.1"),
		sha256Dsa: toBuffer("2.16.840.1.101.3.4.3.2"),
		sha384Dsa: toBuffer("2.16.840.1.101.3.4.3.3"),
		sha512Dsa: toBuffer("2.16.840.1.101.3.4.3.4"),
	},
	at: {
		aliasedEntryName: toBuffer("2.5.4.1"),
		knowldgeinformation: toBuffer(" 2.5.4.2"),
		commonName: toBuffer(" 2.5.4.3"),
		surname: toBuffer("2.5.4.4"),
		serialNumber: toBuffer("2.5.4.5"),
		countryName: toBuffer("2.5.4.6"),
		localityName: toBuffer("2.5.4.7"),
		stateOrProvinceName: toBuffer("2.5.4.8"),
		streetAddress: toBuffer("2.5.4.9"),
		organizationName: toBuffer("2.5.4.10"),
		organizationalUnitName: toBuffer("2.5.4.11"),
		title: toBuffer("2.5.4.12"),
		description: toBuffer("2.5.4.13"),
		searchGuide: toBuffer("2.5.4.14"),
		businessCategory: toBuffer("2.5.4.15"),
		postalAddress: toBuffer("2.5.4.16"),
		postalCode: toBuffer("2.5.4.17"),
		postOfficeBox: toBuffer("2.5.4.18"),
		physicalDeliveryOfficeName: toBuffer("2.5.4.19"),
		telephoneNumber: toBuffer("2.5.4.20"),
		telexNumber: toBuffer("2.5.4.21"),
		teletexTerminalIdentifier: toBuffer("2.5.4.22"),
		facsimileTelephoneNumber: toBuffer("2.5.4.23"),
		x121Address: toBuffer("2.5.4.24"),
		internationalISDNNumber: toBuffer("2.5.4.25"),
		registeredAddress: toBuffer("2.5.4.26"),
		destinationIndicator: toBuffer("2.5.4.27"),
		preferredDeliveryMethod: toBuffer("2.5.4.28"),
		presentationAddress: toBuffer("2.5.4.29"),
		supportedApplicationContext: toBuffer("2.5.4.30"),
		member: toBuffer("2.5.4.31"),
		owner: toBuffer("2.5.4.32"),
		roleOccupant: toBuffer("2.5.4.33"),
		seeAlso: toBuffer("2.5.4.34"),
		userPassword: toBuffer("2.5.4.35"),
		userCertificate: toBuffer("2.5.4.36"),
		cACertificate: toBuffer("2.5.4.37"),
		authorityRevocationList: toBuffer("2.5.4.38"),
		certificateRevocationList: toBuffer("2.5.4.39"),
		crossCertificatePair: toBuffer("2.5.4.40"),
		name: toBuffer("2.5.4.41"),
		givenName: toBuffer("2.5.4.42"),
		initials: toBuffer("2.5.4.43"),
		generationQualifier: toBuffer("2.5.4.44"),
		uniqueIdentifier: toBuffer("2.5.4.45"),
		dnQualifier: toBuffer("2.5.4.46"),
		enhancedSearchGuide: toBuffer("2.5.4.47"),
		protocolInformation: toBuffer("2.5.4.48"),
		distinguishedName: toBuffer("2.5.4.49"),
		uniqueMember: toBuffer("2.5.4.50"),
		houseIdentifier: toBuffer("2.5.4.51"),
		supportedAlgorithms: toBuffer("2.5.4.52"),
		deltaRevocationList: toBuffer("2.5.4.53"),
		attributeCertificate: toBuffer("2.5.4.58"),
		pseudonym: toBuffer("2.5.4.65"),
	},
	pat: { // pilot attribute type
		uid: toBuffer("0.9.2342.19200300.100.1.1"),
		textEncodedORAddress: toBuffer("0.9.2342.19200300.100.1.2"),
		mail: toBuffer("0.9.2342.19200300.100.1.3"),
		info: toBuffer("0.9.2342.19200300.100.1.4"),
		drink: toBuffer("0.9.2342.19200300.100.1.5"),
		roomNumber: toBuffer("0.9.2342.19200300.100.1.6"),
		photo: toBuffer("0.9.2342.19200300.100.1.7"),
		userClass: toBuffer("0.9.2342.19200300.100.1.8"),
		host: toBuffer("0.9.2342.19200300.100.1.9"),
		manager: toBuffer("0.9.2342.19200300.100.1.10"),
		documentIdentifier: toBuffer("0.9.2342.19200300.100.1.11"),
		documentTitle: toBuffer("0.9.2342.19200300.100.1.12"),
		documentVersion: toBuffer("0.9.2342.19200300.100.1.13"),
		documentAuthor: toBuffer("0.9.2342.19200300.100.1.14"),
		documentLocation: toBuffer("0.9.2342.19200300.100.1.15"),
		homeTelephoneNumber: toBuffer("0.9.2342.19200300.100.1.20"),
		secretary: toBuffer("0.9.2342.19200300.100.1.21"),
		otherMailbox: toBuffer("0.9.2342.19200300.100.1.22"),
		dc: toBuffer("0.9.2342.19200300.100.1.25"),
		aRecord: toBuffer("0.9.2342.19200300.100.1.26"),
		mDRecord: toBuffer("0.9.2342.19200300.100.1.27"),
		mXRecord: toBuffer("0.9.2342.19200300.100.1.28"),
		nSRecord: toBuffer("0.9.2342.19200300.100.1.29"),
		sOARecord: toBuffer("0.9.2342.19200300.100.1.30"),
		cNAMERecord: toBuffer("0.9.2342.19200300.100.1.31"),
		associatedDomain: toBuffer("0.9.2342.19200300.100.1.37"),
		associatedName: toBuffer("0.9.2342.19200300.100.1.38"),
		homePostalAddress: toBuffer("0.9.2342.19200300.100.1.39"),
		personalTitle: toBuffer("0.9.2342.19200300.100.1.40"),
		mobileTelephoneNumber: toBuffer("0.9.2342.19200300.100.1.41"),
		pagerTelephoneNumber: toBuffer("0.9.2342.19200300.100.1.42"),
		co: toBuffer("0.9.2342.19200300.100.1.43"),
		uniqueIdentifier: toBuffer("0.9.2342.19200300.100.1.44"),
		organizationalStatus: toBuffer("0.9.2342.19200300.100.1.45"),
		janetMailbox: toBuffer("0.9.2342.19200300.100.1.46"),
		mailPreferenceOption: toBuffer("0.9.2342.19200300.100.1.47"),
		buildingName: toBuffer("0.9.2342.19200300.100.1.48"),
		dSAQuality: toBuffer("0.9.2342.19200300.100.1.49"),
		singleLevelQuality: toBuffer("0.9.2342.19200300.100.1.50"),
		subtreeMinimumQuality: toBuffer("0.9.2342.19200300.100.1.51"),
		subtreeMaximumQuality: toBuffer("0.9.2342.19200300.100.1.52"),
		personalSignature: toBuffer("0.9.2342.19200300.100.1.53"),
		dITRedirect: toBuffer("0.9.2342.19200300.100.1.54"),
		audio: toBuffer("0.9.2342.19200300.100.1.55"),
		documentPublisher: toBuffer("0.9.2342.19200300.100.1.56"),
		jpegPhoto: toBuffer("0.9.2342.19200300.100.1.60"),
	},
	ce: {
		oldAuthorityKeyIdentifier: toBuffer("2.5.29.1"),
		oldPrimaryKeyAttributes: toBuffer("2.5.29.2"),
		certificatePolicies3: toBuffer("2.5.29.3"),
		primaryKeyUsageRestriction: toBuffer("2.5.29.4"),
		subjectDirectoryAttributes: toBuffer("2.5.29.9"),
		subjectKeyIdentifier: toBuffer("2.5.29.14"),
		keyUsage: toBuffer("2.5.29.15"),
		privateKeyUsagePeriod: toBuffer("2.5.29.16"),
		subjectAlternativeName: toBuffer("2.5.29.17"),
		issuerAlternativeName: toBuffer("2.5.29.18"),
		basicConstraints: toBuffer("2.5.29.19"),
		crlNumber: toBuffer("2.5.29.20"),
		reasoncode: toBuffer("2.5.29.21"),
		holdInstructionCode: toBuffer("2.5.29.23"),
		invalidityDate: toBuffer("2.5.29.24"),
		deltaCrlIndicator: toBuffer("2.5.29.27"),
		issuingDistributionPoint: toBuffer("2.5.29.28"),
		certificateIssuer: toBuffer("2.5.29.29"),
		nameConstraints: toBuffer("2.5.29.30"),
		crlDistributionPoints: toBuffer("2.5.29.31"),
		certificatePolicies: toBuffer("2.5.29.32"),
		policyMappings: toBuffer("2.5.29.33"),
		authorityKeyIdentifier: toBuffer("2.5.29.35"),
		policyConstraints: toBuffer("2.5.29.36"),
		extendedKeyUsage: toBuffer("2.5.29.37"),
		freshestCrl: toBuffer("2.5.29.46"),
		inhibitAnyPolicy: toBuffer("2.5.29.54"),
	},
	pkixpe: {
		authorityInfoAccess: toBuffer("1.3.6.1.5.5.7.1.1"),
		biometricInfo: toBuffer("1.3.6.1.5.5.7.1.2"),
		qcStatements: toBuffer("1.3.6.1.5.5.7.1.3"),
		logotype: toBuffer("1.3.6.1.5.5.7.1.12"),
	},
	netscape: {
		certificateType: toBuffer("2.16.840.1.113730.1.1"),
		baseUrl: toBuffer("2.16.840.1.113730.1.2"),
		revocationUrl: toBuffer("2.16.840.1.113730.1.3"),
		caRevocationUrl: toBuffer("2.16.840.1.113730.1.4"),
		renewalUrl: toBuffer("2.16.840.1.113730.1.7"),
		caPolicyUrl: toBuffer("2.16.840.1.113730.1.8"),
		sslServerName: toBuffer("2.16.840.1.113730.1.12"),
		certificateComment: toBuffer("2.16.840.1.113730.1.13"),
	},
	microsoftSpc: {
		indirectData: toBuffer("1.3.6.1.4.1.311.2.1.4"),
		statementType: toBuffer("1.3.6.1.4.1.311.2.1.11"),
		spOpusInfo: toBuffer("1.3.6.1.4.1.311.2.1.12"),
		peImageData: toBuffer("1.3.6.1.4.1.311.2.1.15"),
		spAgencyInfo: toBuffer("1.3.6.1.4.1.311.2.1.10"),
		minimalCriteria: toBuffer("1.3.6.1.4.1.311.2.1.26"),
		financialCriteria: toBuffer("1.3.6.1.4.1.311.2.1.27"),
		link: toBuffer("1.3.6.1.4.1.311.2.1.28"),
		hashInfo: toBuffer("1.3.6.1.4.1.311.2.1.29"),
		sipInfo: toBuffer("1.3.6.1.4.1.311.2.1.30"),
	},
};

var names = exports.names = {};

Object.keys(OIDS).forEach(function(ns) {
	Object.keys(OIDS[ns]).forEach(function(k) {
		names[fromBuffer(OIDS[ns][k])] = ns + "." + k;
	});
});

exports.toString = function(buf) {
	var path = fromBuffer(buf);
	return path + " (" + names[path] + ")";
};