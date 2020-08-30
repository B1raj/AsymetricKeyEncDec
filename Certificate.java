import java.io.FileInputStream;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;


public class Certificate {


    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----\n";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    private static final String ALGORITHM = "RSA";

    public static void main(String[] args) throws Exception {
        String certPath = "/keystore.jks";
        String alias = "client";
        String password = "password";

        try (FileInputStream is = new FileInputStream(certPath)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] passwd = password.toCharArray();
            keystore.load(is, passwd);
            java.security.cert.Certificate certificate = keystore.getCertificate(alias);

            System.out.println(printCertificateByAlias(certificate));

            Key key = keystore.getKey(alias, passwd);
            encryptDecrypt(key, certificate);
        } catch (Exception e) {
            System.out.println("Exception occurred..");
        }

    }

    private static void encryptDecrypt(Key key, java.security.cert.Certificate cert) throws Exception {

        byte[] publicKey = cert.getPublicKey().getEncoded();
        byte[] privateKey = key.getEncoded();
        byte[] encryptedData = encrypt(publicKey,
                "hi this is Biraj here".getBytes());
        byte[] decryptedData = decrypt(privateKey, encryptedData);
        System.out.println(new String(decryptedData));
    }

    protected static String printCertificateByAlias(java.security.cert.Certificate cert) throws CertificateEncodingException {
        Base64 encoder = new Base64(64);
        String publicKeyString = Base64.encodeBase64String(cert.getEncoded());
        String pemCertPre = new String(encoder.encode(cert.getEncoded()));
        return BEGIN_CERT + pemCertPre + END_CERT;

    }

    public static byte[] encrypt(byte[] publicKey, byte[] inputData)
            throws Exception {

        PublicKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(publicKey));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(inputData);
    }

    public static byte[] decrypt(byte[] privateKey, byte[] inputData)
            throws Exception {

        PrivateKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(inputData);
    }


}
