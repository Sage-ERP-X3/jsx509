
Functions and classes for handling certificates and private keys
## Verify integrity of certificate, private key, passphrase, CA certificates
 When CA certificates are given, find out whether one of them signs the given certificate
 result is object with attributes: 
 - key: decrypted private key (if available)
 - cert: certificate object
 - error: error string if error has occurred
## Strip the encryption from a private key
   `stripEncryption(key, passphrase, test)`
  Arguments are a private key in PEM format and the passphrase. The output will be the private key without encryption in PEM format.
  When the private key has not been encrypted, the passphrase will be ignored and the private key will be returned unchanged.
  If the optional 3rd parameter `test` is set, the function parses the resulting private key to check whether it has the correct format (ASN.1).
# X509 certificate class

* `cert = new Certificate(buf)`  
  Creates a new certificate object from an X509 buffer or a PEM content
* `str = cert.toString()`  
  Returns the contents of the certificate in tree form
* `subject = cert.subject`  
  Returns the subject information (see source for list of fields returned);
* `subjectDn = cert.subjectDn`
  Returns the distinguished name of the subject information in a single string
* `issuer = cert.issuer`  
  Returns the issuer information (see source for list of fields returned);
* `issuerDn = cert.issuerDn`
  Returns the distinguished name of the subject information in a single string
* `notAfter = cert.notAfter`  
  Returns the expiry time (number of milliseconds after 1 Jan 1970). The result can be used directly 
  as argument for the constructor of a Date object 
* `notBefore = cert.notBefore`  
  Returns the time at which the certificate will start to be valid (number of milliseconds after 1 Jan 1970).  
  The result can be used directly as argument for the constructor of a Date object 
* `publicKey = cert.publicKey`  
  Returns a buffer with the public key of the certificate  
* `verify(certificate)`
  Verifies the signature of this certificate against the public key of the certificate 
  as given in the parameter (certificate object or string with PEM format)
  Result is true, when the verification is successful.
