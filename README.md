# AsymetricKeyEncDec

### Dependency
 * apache.commons.codec

### Creating keystore
keytool -genkey -keystore keystore.jks -alias client -keyalg RSA -sigalg SHA256withRSA -validity 365 -keysize 2048

### Verify keystore
 keytool -list -rfc -keystore keystore.jks -alias client -storepass <password>
 

