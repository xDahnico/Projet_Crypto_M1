import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

public class SignatureVerification {

    public static boolean verifyRSASignature(X509Certificate cert, PublicKey publicKey) {
        try {
            byte[] signature = cert.getSignature();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            BigInteger n = rsaPublicKey.getModulus();
            BigInteger e = rsaPublicKey.getPublicExponent();

            BigInteger sigInt = new BigInteger(1, signature);
            BigInteger decrypted = sigInt.modPow(e, n);
            byte[] decryptedBytes = decrypted.toByteArray();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] expectedHash = digest.digest(cert.getTBSCertificate());

            if (decryptedBytes.length > expectedHash.length) {
                int diff = decryptedBytes.length - expectedHash.length;
                decryptedBytes = Arrays.copyOfRange(decryptedBytes, diff, decryptedBytes.length);
            }

            if (Arrays.equals(decryptedBytes, expectedHash)) {
                System.out.println("RSA Signature is valid.");
                return true;
            } else {
                System.err.println("RSA Signature verification failed.");
                return false;
            }
        } catch (Exception ex) {
            System.err.println("Error verifying RSA signature: " + ex.getMessage());
            return false;
        }
    }

    public static boolean verifyECDSASignature(X509Certificate cert, PublicKey publicKey) {
        try {
            byte[] signatureBytes = cert.getSignature();
            ASN1Sequence sequence = ASN1Sequence.getInstance(signatureBytes);
            BigInteger r = ((ASN1Integer) sequence.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer) sequence.getObjectAt(1)).getPositiveValue();

            org.bouncycastle.jce.interfaces.ECPublicKey bcPublicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
            org.bouncycastle.jce.spec.ECParameterSpec ecSpec = bcPublicKey.getParameters();

            byte[] tbsCertificate = cert.getTBSCertificate();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(tbsCertificate);

            BigInteger e = new BigInteger(1, hash);
            BigInteger n = ecSpec.getN();
            BigInteger sInv = s.modInverse(n);
            BigInteger u1 = e.multiply(sInv).mod(n);
            BigInteger u2 = r.multiply(sInv).mod(n);

            org.bouncycastle.math.ec.ECPoint G = ecSpec.getG();
            org.bouncycastle.math.ec.ECPoint Q = ((org.bouncycastle.jce.interfaces.ECPublicKey)publicKey).getQ();
            org.bouncycastle.math.ec.ECPoint P = G.multiply(u1).add(Q.multiply(u2));

            BigInteger Px = P.normalize().getXCoord().toBigInteger();

            if (r.compareTo(Px) == 0) {
                System.out.println("ECDSA Signature is valid.");
                return true;
            } else {
                System.err.println("ECDSA Signature verification failed.");
                return false;
            }
        } catch (Exception ex) {
            System.err.println("Error verifying ECDSA signature: " + ex.getMessage());
            return false;
        }
    }
}
