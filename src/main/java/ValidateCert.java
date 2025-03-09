import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;


public class ValidateCert{
    public static void main(String[] args){
        try{
            if(args.length < 4 || !args[0].equalsIgnoreCase("-format") || !(args[1].equalsIgnoreCase("DER") || args[1].equalsIgnoreCase("PEM"))){
                System.out.println("Usage: validate-cert-chain -format DER|PEM <root_cert> <inter_cert> <leaf_cert>");
                return;
            }

            if (Security.getProvider("BC") == null){
                Security.addProvider(new BouncyCastleProvider());
            }
            
            String format = args[1];
            String[] certFiles = Arrays.copyOfRange(args, 2, args.length);
            validateCertificateChain(format, certFiles);
            return;
        }
        catch (Exception e){
                System.err.println("An unexpected error occurred: " + e.getMessage());
                return;
        }

    }

    public static X509Certificate loadCertificate(String certPath, String format) throws Exception{
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream certInputStream = new FileInputStream(certPath)){
            return (X509Certificate) factory.generateCertificate(certInputStream);
        }
    }

    private static boolean verifyKeyUsage(boolean[] keyUsage, int certLevel){
        if (keyUsage == null){
            System.out.println("KeyUsage extension is absent.");
            return false;
        }
    
        // Définition des labels de KeyUsage
        String[] keyUsageLabels ={
            "Digital Signature",   // 0
            "Non Repudiation",     // 1
            "Key Encipherment",    // 2
            "Data Encipherment",   // 3
            "Key Agreement",       // 4
            "Certificate Signing", // 5
            "CRL Signing",         // 6
            "Encipher Only",       // 7
            "Decipher Only"        // 8
        };
        
        // Afficher les permissions KeyUsage
        for (int i = 0; i < keyUsage.length && i < keyUsageLabels.length; i++){
            System.out.println("\t" + keyUsageLabels[i] + " ➝ " + (keyUsage[i] ? "✅ Allowed" : "❌ Not Allowed"));
        }
    
        boolean isValid = false;
        switch(certLevel){
            case 0:
                if(keyUsage.length > 0 && keyUsage[0]){  //0 = Digital Signature
                    isValid = true;
                } 
                else{
                    System.err.println("Invalid KeyUsage for Leaf Certificate: 'Digital Signature' must be enabled.");
                }
                break;
    
            case -1:
                if(keyUsage.length > 6 && keyUsage[5] && keyUsage[6]){  //5 = Certificate Signing, 6 = CRL Signing
                    isValid = true;
                } 
                else{
                    System.err.println("Invalid KeyUsage for Root CA: 'Certificate Signing' and 'CRL Signing' must be enabled.");
                }
                break;
    
            default:
                if(keyUsage.length > 6 && keyUsage[5] && keyUsage[6]){  //5 = Certificate Signing, 6 = CRL Signing
                    isValid = true;
                } 
                else{
                    System.err.println("Invalid KeyUsage for Intermediate CA: 'Certificate Signing' and 'CRL Signing' must be enabled.");
                }
                break;
        }
        return isValid;
    }
    private static boolean verifyBasicConstraints(X509Certificate cert, int certLevel){
        try{
            System.out.println("");
            int basicConstraints = cert.getBasicConstraints();      
            switch(certLevel){
                    case -1:  //Root
                    if(basicConstraints == 0){
                        System.out.println("Root certificate is not a CA.");
                        return false;
                    }
                    else{
                        System.err.println("Root CA valid, path lenght: " + basicConstraints);
                        return true;
                    }

                case 0:  //Leaf
                    if(basicConstraints == -1){
                        System.out.println("Leaf certificate is not a CA: " + basicConstraints);
                        return true;
                    }
                    else{
                        System.err.println("Error: Basic constraint: " + basicConstraints + " is not allowed for Leaf CA.");
                        return false;
                    }
        
                default:  //Intermediate
                    if(basicConstraints < 0){
                        System.out.println("Intermediate certificate is not a CA: " + basicConstraints);
                        return false;
                    }
                    else{
                        System.out.println("CA path lenght: " + basicConstraints);
                        return true;
                    }
            } 
        }
        catch(Exception e){
            System.err.println("Error verifying BasicConstraints: " + e.getMessage());
            return false;
        }
    }

    private static boolean verifyRSASignature(X509Certificate cert, PublicKey publicKey){
        try{
            byte[] signature = cert.getSignature();
    
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            BigInteger n = rsaPublicKey.getModulus();  // Modulus
            BigInteger e = rsaPublicKey.getPublicExponent(); // Exponent
    
            BigInteger sigInt = new BigInteger(1, signature);  //Convert the signature into an integer

    
            BigInteger decrypted = sigInt.modPow(e, n);
            byte[] decryptedBytes = decrypted.toByteArray();
    
            MessageDigest digest = MessageDigest.getInstance("SHA-256");  //Compute expected hash

            byte[] expectedHash = digest.digest(cert.getTBSCertificate());
    
            if (decryptedBytes.length > expectedHash.length){
                int diff = decryptedBytes.length - expectedHash.length;
                decryptedBytes = Arrays.copyOfRange(decryptedBytes, diff, decryptedBytes.length);
            }
    
            if(Arrays.equals(decryptedBytes, expectedHash)){
                System.out.println("RSA Signature is valid.");
                return true;
            } 
            else{
                System.err.println("RSA Signature verification failed.");
                return false;
            }
        } 
        catch (Exception ex){
            System.err.println("Error verifying RSA signature: " + ex.getMessage());
            return false;
        }
    }
      
    public static boolean verifyECDSASignature(X509Certificate cert, PublicKey publicKey) throws Exception{
        try{
            byte[] signatureBytes = cert.getSignature();
            ECPublicKey bcPublicKey = (ECPublicKey) publicKey;
    
            ASN1Sequence sequence = ASN1Sequence.getInstance(signatureBytes);
            BigInteger r = new BigInteger(1, ((ASN1Integer) sequence.getObjectAt(0)).getEncoded());
            BigInteger s = new BigInteger(1, ((ASN1Integer) sequence.getObjectAt(1)).getEncoded());

            ECParameterSpec ecSpec = bcPublicKey.getParameters();
            BigInteger n = ecSpec.getN();

            byte[] tbsCertificate = cert.getTBSCertificate();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(tbsCertificate);

            BigInteger e = new BigInteger(1, hash).mod(n);
            BigInteger sInv = s.modInverse(n); 
            BigInteger u1 = e.multiply(sInv).mod(n); 
            BigInteger u2 = r.multiply(sInv).mod(n);

            ECPoint G = ecSpec.getG();
            org.bouncycastle.math.ec.ECPoint Q = bcPublicKey.getQ();
            org.bouncycastle.math.ec.ECPoint P = G.multiply(u1).add(Q.multiply(u2));

            BigInteger Px = P.normalize().getXCoord().toBigInteger();

            if (r.compareTo(Px) != 0){
                return false;
            }
            return true;
        }
        catch (Exception ex){
            System.err.println("Error verifying ECDSA signature: " + ex.getMessage());
            return false;
        }
    }
    
    public static boolean validateCertificate(X509Certificate subjectCert, X509Certificate issuerCert, int certLevel) throws NoSuchAlgorithmException, InvalidKeyException{
        /* 
            Check the certificate and verify with the issuer certificate
        */
        try{   
            System.out.println("\n- Subject: " + subjectCert.getSubjectX500Principal());
            System.out.println("- Issuer: " + issuerCert.getSubjectX500Principal());

            if(!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())){  //Check subjectCert issuer == issuerCert subject 
                System.err.println("Error: Issuer mismatch between " +
                        subjectCert.getIssuerX500Principal() + " and " + issuerCert.getSubjectX500Principal());
                return false;
            }

            PublicKey issuerPublicKey = issuerCert.getPublicKey(); 
            try{
                if(issuerPublicKey instanceof RSAPublicKey){  //Check if issuerCert public key is RSA
                    if(!verifyRSASignature(subjectCert, issuerPublicKey)){  //Check RSA signature
                        System.err.println("RSA Signature verification failed.");
                        return false;
                    }
                } 
                else if(issuerPublicKey instanceof ECPublicKey){  //Check if issuerCert public key is ECDSA
                    if (!verifyECDSASignature(subjectCert, issuerPublicKey)){  //Check ECDSA signature
                        System.err.println("ECDSA Signature verification failed.");
                        return false;
                    }
                }
            } 
            catch (Exception ex){
                System.err.println("Error verifying signature: " + ex.getMessage());
                return false;
            }
            
            if(!verifyKeyUsage(issuerCert.getKeyUsage(), certLevel)){  //Check if the issuer is allowed to sign certificate
                System.err.println("Issuer not allowed to sign certificate.");
                return false;
            }

            if(!verifyBasicConstraints(subjectCert, certLevel)){  //Check basic constraints
                System.err.println("Error: Basic Constraints not valid for this certificate level.");
                return false;
            }

            subjectCert.checkValidity();
            System.out.println("\nCertificate is within valid date range.\n\tFrom: "+ subjectCert.getNotBefore()+ "\n\tUntil: " + subjectCert.getNotAfter()+"\n");

            System.out.println("Certificate validation successful.\n\n");
            return true;
        } 
        catch(CertificateExpiredException e){
            System.err.println("Certificate is expired.");
        } 
        catch(CertificateNotYetValidException e){
            System.err.println("Certificate is not yet valid.");
        }   
        return false;
    }   

    private static boolean validateRootCertificate(X509Certificate rootCert){
        /*
          Check the root certificate
        */
        try{
            System.out.println("\n- Subject: " + rootCert.getSubjectX500Principal());
            System.out.println("- Issuer: " + rootCert.getIssuerX500Principal()+"\n");

            if(!rootCert.getSubjectX500Principal().equals(rootCert.getIssuerX500Principal())){  //Check issuer == subject
                System.err.println("Error: Issuer mismatch between " +
                rootCert.getIssuerX500Principal() + " and " + rootCert.getSubjectX500Principal());
                return false;
            }

            try{  //Check self-signed
                rootCert.verify(rootCert.getPublicKey());
                System.out.println("Root Certificate is correctly self-signed.");
            } 
            catch(Exception e){
                System.err.println("Root certificate signature verification failed: " + e.getMessage());
                return false;
            }
            
            boolean[] keyUsage = rootCert.getKeyUsage();  //Check key usage
            if(!verifyKeyUsage(keyUsage, -1)){
                System.err.println("Key usage is not correct, certificate not allowed to sign other certificates.");
                return false;
            }

            PublicKey rootPublicKey = rootCert.getPublicKey();
            try{
                if(rootPublicKey instanceof RSAPublicKey){  //Check if issuerCert public key is RSA
                    if(!verifyRSASignature(rootCert, rootPublicKey)){  //Check RSA signature
                        System.err.println("RSA Signature verification failed.");
                        return false;
                    }
                } 
                else if (rootPublicKey instanceof ECPublicKey){  //Check if issuerCert public key is ECDSA
                    if (!verifyECDSASignature(rootCert, rootPublicKey)){  //Check ECDSA signature
                        System.err.println("ECDSA Signature verification failed.");
                        return false;
                    }
                }
            } 
            catch (Exception ex){
                System.err.println("Error verifying signature: " + ex.getMessage());
                return false;
            }
            
            if(!verifyBasicConstraints(rootCert, -1)){  //Check basic constraints
                System.err.println("Error: Basic Constraints not valid for this certificate level.");
                return false;
            }

            rootCert.checkValidity();
            System.out.println("\nCertificate is within valid date range.\n\tFrom: "+ rootCert.getNotBefore()+ "\n\tUntil: " + rootCert.getNotAfter()+"\n");
            System.out.println("Root certificate valid!\n");

            return true;
        }
        catch(CertificateExpiredException e){
            System.err.println("Certificate is expired.");
        }
        catch(CertificateNotYetValidException e){
            System.err.println("Certificate is not yet valid.");
        }
        return false;
    }

    public static boolean validateCertificateChain(String format, String[] certFiles){
        try{
            X509Certificate[] certChain = new X509Certificate[certFiles.length];
    
            for (int i = 0; i < certFiles.length - 1; i++){
                certChain[i] = loadCertificate(certFiles[i], format);
                X509Certificate issuerCert = loadCertificate(certFiles[i+1], format);
                if (!validateCertificate(certChain[i], issuerCert, i))
                    return false;
            }

            X509Certificate rootCert = loadCertificate(certFiles[certFiles.length - 1], format);
            if(!validateRootCertificate(rootCert)){
                System.out.println("\n Not a root certificate!");
                return false;
            }

            System.out.println("\n\n\nThe certificate chain is valid!");
            return true;
        } 

        catch (Exception e){
            System.err.println(" Error: " + e.getMessage());
            return false;
        }
    }
 
}