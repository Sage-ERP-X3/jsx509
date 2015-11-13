"use strict";

QUnit.module(module.id);

var jsx509 = require('../..')
var oids = jsx509.oids;
var x509 = jsx509.x509;
var Certificate = jsx509.Certificate;
var stripEncryption = jsx509.stripEncryption;
var integrity = jsx509.integrity;
var fs = require('fs');

test("oids roundtrip", 188, function() {
	Object.keys(oids.names).forEach(function(k) {
		strictEqual(oids.fromBuffer(oids.toBuffer(k)), k, oids.names[k] + ': ' + k);
	});
});

var cert = "308204eb308203d3a00302010202102069810a9ac51343d003816bac3ec14e300d06092a864886f70d01010505003081b6310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313b3039060355040b13325465726d73206f66207573652061742068747470733a2f2f7777772e766572697369676e2e636f6d2f7270612028632930393130302e06035504031327566572695369676e20436c617373203320436f6465205369676e696e6720323030392d32204341301e170d3130303731343030303030305a170d3133303731333233353935395a3081a8310b3009060355040613024652310f300d060355040813064672616e6365310e300c06035504071305506172697331143012060355040a140b53414745204652414e4345313e303c060355040b13354469676974616c20494420436c6173732033202d204d6963726f736f667420536f6674776172652056616c69646174696f6e207632310c300a060355040b1403522644311430120603550403140b53414745204652414e434530819f300d06092a864886f70d010101050003818d0030818902818100887490bd6a939a3c42d3a56f99eb6fb3f45fa5c969f733392e6be15830e7eddf90d3537743f2a39709aa9552fd405f2b789688a9c3d70d2de4f0bbcd4e9aab43797836f47961ee8753323771653f12824b3aab5850aa890e267f49246a261834f6b4575d4ef72c785d5ce874398659ee8ca28a5f33b3ab65c2e47a3ad62e32a70203010001a38201833082017f30090603551d1304023000300e0603551d0f0101ff04040302078030440603551d1f043d303b3039a037a0358633687474703a2f2f637363332d323030392d322d63726c2e766572697369676e2e636f6d2f435343332d323030392d322e63726c30440603551d20043d303b3039060b6086480186f84501071703302a302806082b06010505070201161c68747470733a2f2f7777772e766572697369676e2e636f6d2f72706130130603551d25040c300a06082b06010505070303307506082b0601050507010104693067302406082b060105050730018618687474703a2f2f6f6373702e766572697369676e2e636f6d303f06082b060105050730028633687474703a2f2f637363332d323030392d322d6169612e766572697369676e2e636f6d2f435343332d323030392d322e636572301f0603551d2304183016801497d06ba82670c8a13f941f082dc4359ba4a11ef2301106096086480186f84201010404030204103016060a2b06010401823702011b040830060101000101ff300d06092a864886f70d0101050500038201010093d02a36e4410e14868dc38009e278782ff25481ca2889496389637f94fd09b151ffcb9efae50cf76559b5e349421f0429f66ffc06797e024bf2feb15c4e63eb5610a8c72313ba64f7470a73b41d5a474c286d07e50ffc1051f07b150cee29a2c0be4db9a929ae95b51213e421c1bff03f39b086a9d63ba885aee81cb1ff3b517efa58ee3606f6f8830a6f971aab59b1991e9f65779b5cc9ba22ae496c1a5469b92497c60e835707e533891784d17cfe9a860b87ed80d712ad4532252c0a892f6463eba6f915e71c8295074d2ec629df6bb7efb90acf2427eefa1807d693ae0add24da97c53ed73a58b13faca0390e327b24d1b5b009f80b0b540a74799951f2";
var hash = "6dfe4827e63a2131e70364b08c846dfee44da919";
var signature = "227c2f36ab6fa90ed6f2e3b3c021f6a8043700af9e8492c67656d3f0d1d6d9b96000d57fef73d83c6ec92e61aa74d2945209a02a1a16b919074d7d530913c61719c4e408eace2ae87faa88a75e1ee4fb4da502a1363975d30bf04f5970acb9a19117d4a39e4d7e618606d3aeefcba20e11dd165e816a08a5286a92906dbe5dad";
var expectedSign = "308206b106092a864886f70d010702a08206a23082069e020101310b300906052b0e03021a0500302306092a864886f70d010701a01604146dfe4827e63a2131e70364b08c846dfee44da919a08204ef308204eb308203d3a00302010202102069810a9ac51343d003816bac3ec14e300d06092a864886f70d01010505003081b6310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313b3039060355040b13325465726d73206f66207573652061742068747470733a2f2f7777772e766572697369676e2e636f6d2f7270612028632930393130302e06035504031327566572695369676e20436c617373203320436f6465205369676e696e6720323030392d32204341301e170d3130303731343030303030305a170d3133303731333233353935395a3081a8310b3009060355040613024652310f300d060355040813064672616e6365310e300c06035504071305506172697331143012060355040a140b53414745204652414e4345313e303c060355040b13354469676974616c20494420436c6173732033202d204d6963726f736f667420536f6674776172652056616c69646174696f6e207632310c300a060355040b1403522644311430120603550403140b53414745204652414e434530819f300d06092a864886f70d010101050003818d0030818902818100887490bd6a939a3c42d3a56f99eb6fb3f45fa5c969f733392e6be15830e7eddf90d3537743f2a39709aa9552fd405f2b789688a9c3d70d2de4f0bbcd4e9aab43797836f47961ee8753323771653f12824b3aab5850aa890e267f49246a261834f6b4575d4ef72c785d5ce874398659ee8ca28a5f33b3ab65c2e47a3ad62e32a70203010001a38201833082017f30090603551d1304023000300e0603551d0f0101ff04040302078030440603551d1f043d303b3039a037a0358633687474703a2f2f637363332d323030392d322d63726c2e766572697369676e2e636f6d2f435343332d323030392d322e63726c30440603551d20043d303b3039060b6086480186f84501071703302a302806082b06010505070201161c68747470733a2f2f7777772e766572697369676e2e636f6d2f72706130130603551d25040c300a06082b06010505070303307506082b0601050507010104693067302406082b060105050730018618687474703a2f2f6f6373702e766572697369676e2e636f6d303f06082b060105050730028633687474703a2f2f637363332d323030392d322d6169612e766572697369676e2e636f6d2f435343332d323030392d322e636572301f0603551d2304183016801497d06ba82670c8a13f941f082dc4359ba4a11ef2301106096086480186f84201010404030204103016060a2b06010401823702011b040830060101000101ff300d06092a864886f70d0101050500038201010093d02a36e4410e14868dc38009e278782ff25481ca2889496389637f94fd09b151ffcb9efae50cf76559b5e349421f0429f66ffc06797e024bf2feb15c4e63eb5610a8c72313ba64f7470a73b41d5a474c286d07e50ffc1051f07b150cee29a2c0be4db9a929ae95b51213e421c1bff03f39b086a9d63ba885aee81cb1ff3b517efa58ee3606f6f8830a6f971aab59b1991e9f65779b5cc9ba22ae496c1a5469b92497c60e835707e533891784d17cfe9a860b87ed80d712ad4532252c0a892f6463eba6f915e71c8295074d2ec629df6bb7efb90acf2427eefa1807d693ae0add24da97c53ed73a58b13faca0390e327b24d1b5b009f80b0b540a74799951f2318201723082016e0201013081cb3081b6310b300906035504061302555331173015060355040a130e566572695369676e2c20496e632e311f301d060355040b1316566572695369676e205472757374204e6574776f726b313b3039060355040b13325465726d73206f66207573652061742068747470733a2f2f7777772e766572697369676e2e636f6d2f7270612028632930393130302e06035504031327566572695369676e20436c617373203320436f6465205369676e696e6720323030392d3220434102102069810a9ac51343d003816bac3ec14e300906052b0e03021a0500300d06092a864886f70d0101010500048180227c2f36ab6fa90ed6f2e3b3c021f6a8043700af9e8492c67656d3f0d1d6d9b96000d57fef73d83c6ec92e61aa74d2945209a02a1a16b919074d7d530913c61719c4e408eace2ae87faa88a75e1ee4fb4da502a1363975d30bf04f5970acb9a19117d4a39e4d7e618606d3aeefcba20e11dd165e816a08a5286a92906dbe5dad";

test("signature roundtrip", 3, function() {
	var gotSign = x509.buildSignature(new Buffer(cert, "hex"), new Buffer(hash, "hex"), new Buffer(signature, "hex"));

	strictEqual(gotSign.toString("hex"), expectedSign, "roundtrip ok");
	ok(x509.guessSignatureSize(new Buffer(cert, "hex")) >= gotSign.length + 3 * 148, "size guess ok");
	ok(x509.guessSignatureSize(new Buffer(cert, "hex")) <= gotSign.length + 3.1 * 148, "size guess not too big");
});

test("strip private key encryption", 2, function() {
	var encrypted = fs.readFileSync(__dirname + "/fixtures/ca.key", "utf8");
	encrypted = encrypted.replace(/\r\n|\r|\n/g, "\n"); // normalize line ending (otherwise test will not work on all platforms)
	var nonEncrypted = fs.readFileSync(__dirname + "/fixtures/ca_ohne.key", "utf8");
	nonEncrypted = nonEncrypted.replace(/\r\n|\r|\n/g, "\n");
	var stripped = stripEncryption(encrypted, "test");
	equal(nonEncrypted, stripped);
	stripped = stripEncryption(nonEncrypted, "test");
	equal(nonEncrypted, stripped);
});

test("certificate verification", 3, function() {
	var caString = fs.readFileSync(__dirname + "/fixtures/ca.crt", "utf8");
	var certString = fs.readFileSync(__dirname + "/fixtures/server.crt", "utf8");
	var ca = new Certificate(caString);
	var cert = new Certificate(certString);
	equal(ca.verify(caString), true, "Self signed certificate");
	equal(cert.verify(ca), true, "Not self signed certificate");
	var result = true;
	try {
		result = cert.verify(certString);
	} catch (e) {
		result = false;
	}
	equal(result, false, "Certificate is not self signed");
});

test("verification of key and certificates", 9, function() {
	var encrypted = fs.readFileSync(__dirname + "/fixtures/server.key", "utf8");
	var caString = fs.readFileSync(__dirname + "/fixtures/ca.crt", "utf8");
	var nonEncryptedCa = fs.readFileSync(__dirname + "/fixtures/ca_ohne.key", "utf8");
	var certString = fs.readFileSync(__dirname + "/fixtures/server.crt", "utf8");
	var result = integrity(certString, encrypted, "server", [caString]);
	equal(result.error, undefined, "Everything OK");
	equal(result.cert.issuerDn, "C=ab, ST=ab, L=ab, O=ab, OU=ab, CN=ab", "Issuer DN of certificate OK");
	equal(integrity(certString, "blabla", "server", [caString]).error, "Private key does not have PEM format", "Wrong format of key");
	equal(integrity(certString, encrypted, "serv", [caString]).error, "Wrong passphrase", "wrong passphrase");
	equal(integrity(certString, nonEncryptedCa, "serv", [caString]).error, "Key does not fit to certificate", "key does not fit to certificate");
	equal(integrity(certString, encrypted, "server", [certString]).error.substr(0, 18), "Error in verifying", "no fitting CA certificate");
	equal(integrity(certString, encrypted, "server", [encrypted]).error.substr(0, 18), "Error in verifying", "invalid CA certificate");
	equal(integrity(certString, encrypted, "server", ["blabla"]).error.substr(0, 18), "Error in verifying", "CA certificate not in PEM format");
	equal(integrity("blabla", encrypted, "server", [caString]).error, "Certificate does not have PEM format", "Certificate not in PEM format");

});

test("certificate", 19, function() {
	var certif = new Certificate(new Buffer(cert, "hex"));
	equal(certif.subject.countryName, "FR", "countryName ok");
	equal(certif.subject.stateOrProvinceName, "France", "stateOrProvinceName ok");
	equal(certif.subject.localityName, "Paris", "localityName ok");
	equal(certif.subject.organizationName, "SAGE FRANCE", "organizationName ok");
	equal(certif.subject.organizationalUnitNames[0], "Digital ID Class 3 - Microsoft Software Validation v2", "organizationalUnitNames[0] ok");
	equal(certif.subject.organizationalUnitNames[1], "R&D", "organizationalUnitNames[1] ok");
	equal(certif.subject.commonName, "SAGE FRANCE", "commonName ok");
	equal(certif.subjectDn, "C=FR, ST=France, L=Paris, O=SAGE FRANCE, OU=Digital ID Class 3 - Microsoft Software Validation v2, OU=R&D, CN=SAGE FRANCE", "DN ok");
	equal(certif.issuer.countryName, "US", "issuer countryName ok");
	equal(certif.issuer.stateOrProvinceName, undefined, "issuer stateOrProvinceName ok");
	equal(certif.issuer.localityName, undefined, "issuer localityName ok");
	equal(certif.issuer.organizationName, "VeriSign, Inc.", "issuer organizationName ok");
	equal(certif.issuer.organizationalUnitNames[0], "VeriSign Trust Network", "issuer organizationalUnitNames[0] ok");
	equal(certif.issuer.organizationalUnitNames[1], "Terms of use at https://www.verisign.com/rpa (c)09", "issuer organizationalUnitNames[1] ok");
	equal(certif.issuer.commonName, "VeriSign Class 3 Code Signing 2009-2 CA", "issuer commonName ok");
	equal(certif.issuerDn, "C=US, O=VeriSign, Inc., OU=VeriSign Trust Network, OU=Terms of use at https://www.verisign.com/rpa (c)09, CN=VeriSign Class 3 Code Signing 2009-2 CA", "issuer DN ok");
	equal(certif.notBefore, "1279065600000", "start date ok");
	equal(certif.notAfter, "1373759999000", "end date ok");
	var publicKeyHex = "30818902818100887490bd6a939a3c42d3a56f99eb6fb3f45fa5c969f733392e6be15830e7eddf90d3537743f2a39709aa9552fd405f2b789688a9c3d70d2de4f0bbcd4e9aab43797836f47961ee8753323771653f12824b3aab5850aa890e267f49246a261834f6b4575d4ef72c785d5ce874398659ee8ca28a5f33b3ab65c2e47a3ad62e32a70203010001";
	equal(certif.publicKey.toString("hex"), publicKeyHex, "public key ok");
});