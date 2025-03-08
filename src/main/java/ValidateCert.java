import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.util.Arrays;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;



public class ValidateCert{
    public static void main(String[] args){
        if(/*args.length < 4 || */!args[0].equalsIgnoreCase("-format") || !(args[1].equalsIgnoreCase("DER") || args[1].equalsIgnoreCase("PEM"))){
            System.out.println("Usage: validate-cert-chain -format DER|PEM <root_cert> <inter_cert> <leaf_cert>");
            return;
        }
        
        String format = args[1];
        String[] certFiles = Arrays.copyOfRange(args, 2, args.length);


        try {
            X509Certificate cert = loadCertificate(certFiles[0], format);
            X509Certificate issuercert = loadCertificate(certFiles[1], format);

            validateCertificate(cert, issuercert);
    
        } 
        catch (CertificateException  e) {
            System.err.println("Error loading certificate: " + e.getMessage());
        }catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
        }
        //validateCertificateChain(format, certFiles);
    }
    
    private static X509Certificate loadCertificate(String certFile, String format) throws Exception{
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try(InputStream inStream = new FileInputStream(certFile)){
            if(format.equalsIgnoreCase("DER")){
                return(X509Certificate) cf.generateCertificate(inStream);
            } else if(format.equalsIgnoreCase("PEM")){
                return(X509Certificate) cf.generateCertificate(inStream);
            } else{
                throw new IllegalArgumentException("Unsupported format: " + format);
            }
        }
    }

    private static boolean  verifyKeyUsage(boolean[] keyUsage){
        if(keyUsage == null){
            System.out.println("KeyUsage extension is absent.");
            return false;
        }
    
        String[] keyUsageLabels ={
            "Digital Signature",
            "Non Repudiation",
            "Key Encipherment",
            "Data Encipherment",
            "Key Agreement",
            "Certificate Signing",
            "CRL Signing",     
            "Encipher Only",
            "Decipher Only" 
        };
    
        boolean isValid = false;
    
        for(int i = 0; i < keyUsage.length && i < keyUsageLabels.length; i++){
            if(keyUsage[i]){
                System.out.println("\tAllowed: " + keyUsageLabels[i]);
            } 
            else{
                System.out.println("\tNot allowed: " + keyUsageLabels[i]);
            }
        }
    
        if(keyUsage.length > 5 && keyUsage[5]){
            isValid = true;
        } 
    
        System.out.println("");
        return isValid;
    }
    
    private static boolean verifyRSASignature(X509Certificate cert, PublicKey publicKey){
        try{
            byte[] signature = cert.getSignature();

            RSAPublicKey rsaPublicKey =(RSAPublicKey) publicKey;  //Public key of the issuer
            BigInteger n = rsaPublicKey.getModulus();  
            BigInteger e = rsaPublicKey.getPublicExponent(); 

            BigInteger sigInt = new BigInteger(1, signature);
            BigInteger decrypted = sigInt.modPow(e, n);  //Unsign the hash
            byte[] decryptedBytes = decrypted.toByteArray();  //Convert to bytes

            MessageDigest digest = MessageDigest.getInstance("SHA-256");  
            byte[] expectedHash = digest.digest(cert.getTBSCertificate());  //Hash the certificates

            if(Arrays.equals(decryptedBytes, expectedHash)){  //Verify that the hash obtained and the unsigned are equal
                System.out.println("RSA Signature is valid.");
                return true;
            } 
            else{
                return false;
            }
        } 
        catch(Exception ex){
            System.err.println("Error verifying RSA signature: " + ex.getMessage());
            return false;
        }
    }

        public static boolean verifyECDSASignature(X509Certificate cert, PublicKey publicKey) {
        try {
            if (!(publicKey instanceof ECPublicKey)) {
                System.err.println("❌ Error: Public key is not an ECDSA key.");
                return false;
            }

            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ecPublicKey.getParams().toString());
            
            ECField field = ecPublicKey.getParams().getCurve().getField();
            BigInteger p = ((ECFieldFp) field).getP();
            
            ECPoint G = ecSpec.getG();
            ECPoint Q = ((org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey) ecPublicKey).getQ();
            
            byte[] signatureBytes = cert.getSignature();
            int len = signatureBytes.length / 2;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(signatureBytes, 0, len));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(signatureBytes, len, signatureBytes.length));

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] certHash = digest.digest(cert.getTBSCertificate());
            BigInteger e = new BigInteger(1, certHash);

            BigInteger w = s.modInverse(p);
            BigInteger u1 = e.multiply(w).mod(p);
            BigInteger u2 = r.multiply(w).mod(p);
            
            ECPoint P = G.multiply(u1).add(Q.multiply(u2));
            BigInteger x = P.getXCoord().toBigInteger();
            
            if (x.mod(p).equals(r.mod(p))) {
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

    public static boolean validateCertificate(X509Certificate subjectCert, X509Certificate issuerCert){
        /* 
            Check the certificate and verify with the issuer certificate
        */
        try{   
            System.out.println("   - Subject: " + subjectCert.getSubjectX500Principal());
            System.out.println("   - Issuer: " + issuerCert.getSubjectX500Principal());

            subjectCert.checkValidity();  //Check validity period
            if(!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())){  //Check subjectCert issuer == issuerCert subject 
                System.err.println("Error: Issuer mismatch between " +
                        subjectCert.getIssuerX500Principal() + " and " + issuerCert.getSubjectX500Principal());
                return false;
            }

                PublicKey issuerPublicKey = issuerCert.getPublicKey();
                System.out.println("   - Verifying with Public Key: " + issuerCert.getPublicKey());

                if(issuerPublicKey instanceof RSAPublicKey){  //Check isserCert public key is RSA
                    if(!verifyRSASignature(subjectCert, issuerPublicKey)){  //Check RSA signature
                        System.err.println("RSA Signature verification failed.");
                        return false;
                    }
                    else{
                        System.err.println("RSA Signature is valid.");
                    }
                } 
                else if (issuerPublicKey instanceof ECPublicKey) {  //Check if issuerCert public key is ECDSA
                    if (!verifyECDSASignature(subjectCert, issuerPublicKey)) {  //Check ECDSA signature
                        System.err.println("ECDSA Signature verification failed.");
                        return false;
                    } else {
                        System.out.println("ECDSA Signature is valid.");
                    }
                }

                else{  //If not RSA, check public key with other function
                    System.err.println("Non RSA or ECDSA key");
                    String signatureAlgorithm = subjectCert.getSigAlgName(); 
                    Signature signatureInstance = Signature.getInstance(signatureAlgorithm);
                    signatureInstance.initVerify(issuerPublicKey);
                    signatureInstance.update(subjectCert.getTBSCertificate());
        
                    if(signatureInstance.verify(subjectCert.getSignature()))
                        System.out.println("Certificate signature checked\n");
                    else{
                        System.err.println("Error : Wrong certificate signature\n");
                    }
                    System.out.println("Signature verified successfully!");
                }

                if(!verifyKeyUsage(issuerCert.getKeyUsage())){  //Check if the issuer is allowed to sign certificate
                    System.err.println("Issuer not allowed to sign certificate.");
                    return false;
                }

            System.out.println("Certificate validation successful.");
            return true;
        } 
        catch(CertificateExpiredException e){
            System.err.println("Certificate is expired.");
        } 
        catch(CertificateNotYetValidException e){
            System.err.println("Certificate is not yet valid.");
        } 
        catch(SignatureException e){
            System.err.println("Signature error.");
        } 
        catch(NoSuchAlgorithmException e){
            System.err.println("Algorithm is not valid.");
        } 
        catch(InvalidKeyException e){
            System.err.println("Invalid key.");
        } 
        catch(CertificateEncodingException e){
            System.err.println("Invalid key.");
        } 
        
        return false;
    }
    

    private static boolean validateRootCertificate(X509Certificate rootCert){
        /*
          Check the root certificate
        */
        try{
            System.out.println("\n Checking Root Certificate:");
            System.out.println("Subject: " + rootCert.getSubjectX500Principal()+"\n");
            System.out.println("Issuer: " + rootCert.getIssuerX500Principal()+"\n");

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
            if(!verifyKeyUsage(keyUsage)){
                System.err.println("Key usage is not correct, certificate not allowed to sign other certificates.");
                return false;
            }

            byte[] signature = rootCert.getSignature(); 
            String signatureAlgorithm = rootCert.getSigAlgName(); 
            System.out.println("Signature Algorithm: " + signatureAlgorithm+"\n");


            PublicKey rootPublicKey = rootCert.getPublicKey();
                
            if(rootPublicKey instanceof RSAPublicKey){  //Check isserCert public key is RSA
                if(!verifyRSASignature(rootCert, rootPublicKey)){  //Check RSA signature
                    System.err.println("Root RSA Signature verification failed.");
                    return false;
                }
                else{
                    System.err.println("RSA Signature is valid.");
                }
            }
            else if(rootPublicKey instanceof ECPublicKey){  // Check if issuerCert public key is ECDSA
                if (!verifyECDSASignature(rootCert, rootPublicKey)){  // Check ECDSA signature
                    System.err.println("ECDSA Signature verification failed.");
                    return false;
                } else {
                    System.out.println("ECDSA Signature is valid.");
                }
            }
            else{  //If not RSA, check public key with other function
                System.err.println("Non RSA or ECDSA key");
                Signature signatureInstance = Signature.getInstance(signatureAlgorithm);
                signatureInstance.initVerify(rootPublicKey); 
                signatureInstance.update(rootCert.getTBSCertificate());
    
                if(signatureInstance.verify(signature))
                    System.out.println("Certificate signature checked\n");
                else{
                    System.err.println("Error : Wrong certificate signature\n");
                }
                System.out.println("Signature verified successfully!");
            }
            
            rootCert.checkValidity();
            System.out.println("Certificate is within valid date range.\n\tFrom: "+ rootCert.getNotBefore()+ "\n\tUntil: " + rootCert.getNotAfter()+"\n");
            return true;
        }
        catch(CertificateExpiredException e){
            System.err.println("Certificate is expired.");
        }
        catch(CertificateNotYetValidException e){
            System.err.println("Certificate is not yet valid.");
        }
        catch(CertificateException e){
            System.err.println("Certificate exception "+ e.getMessage());
        }
        catch(NoSuchAlgorithmException e){
            System.err.println("Algorithm exception "+ e.getMessage());
        }
        catch(InvalidKeyException e){
            System.err.println("Invalid key "+ e.getMessage());
        }
        catch(SignatureException e){
            System.err.println("Signature exception "+ e.getMessage());
        }
        return false;
    }

    public static boolean validateCertificateChain(String format, String[] certFiles){
        try{
            X509Certificate[] certChain = new X509Certificate[certFiles.length];
    
            for (int i = 0; i < certFiles.length - 1; i++){
                certChain[i] = loadCertificate(certFiles[i], format);
                System.out.println("\nValidating Certificate: " + certChain[i].getSubjectX500Principal());

                if (!validateCertificate(certChain[i], loadCertificate(certFiles[i+1], format))){
                    System.err.println("Invalid certificate detected: " + certFiles[i]);
                    return false;
                }
            }
    
            X509Certificate rootCert = certChain[certChain.length - 1];
            if(!validateRootCertificate(rootCert)){
                System.out.println("\n Not a root certificate!");
                return false;
            }

            System.out.println("\n The certificate chain is valid!");
            return true;
        } 

        catch (Exception e){
            System.err.println(" Error: " + e.getMessage());
            return false;
        }
    }
    
    

}