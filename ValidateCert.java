import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class ValidateCert{
    public static void main(String[] args){
        if(args.length < 4 || !args[0].equalsIgnoreCase("-format") || !(args[1].equalsIgnoreCase("DER") || args[1].equalsIgnoreCase("PEM"))){
            System.out.println("Usage: validate-cert-chain -format DER|PEM <root_cert> <inter_cert> <leaf_cert>");
            return;
        }
        
        String format = args[1];
        String[] certFiles = Arrays.copyOfRange(args, 2, args.length);

        validateCertificateChain(format, certFiles);
        /* 
        try{
            X509Certificate cert = loadCertificate(certFile, format);
            validateCertificate(cert);
        } catch(Exception e){
            System.err.println("Error: " + e.getMessage());
        }*/
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

            RSAPublicKey rsaPublicKey =(RSAPublicKey) publicKey;
            BigInteger n = rsaPublicKey.getModulus();  
            BigInteger e = rsaPublicKey.getPublicExponent(); 

            BigInteger sigInt = new BigInteger(1, signature);
            BigInteger decrypted = sigInt.modPow(e, n);
            byte[] decryptedBytes = decrypted.toByteArray();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] expectedHash = digest.digest(cert.getTBSCertificate());

            if(Arrays.equals(decryptedBytes, expectedHash)){
                System.out.println("RSA Signature is valid.");
                return true;
            } else{
                System.err.println("RSA Signature verification failed.");
                return false;
            }
        } catch(Exception ex){
            System.err.println("Error verifying RSA signature: " + ex.getMessage());
            return false;
        }
    }

    public static boolean validateCertificate(X509Certificate subjectCert, X509Certificate issuerCert){
        /* 
            Check the certificate and verify with the issuer certificate
        */
        try{    
            subjectCert.checkValidity();  //Check validity period
            if(!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())){  //Check subjectCert issuer == issuerCert subject 
                System.err.println("Error: Issuer mismatch between " +
                        subjectCert.getIssuerX500Principal() + " and " + issuerCert.getSubjectX500Principal());
                return false;
            }
    
            try{
                PublicKey issuerPublicKey = issuerCert.getPublicKey();
                
                if(issuerPublicKey instanceof RSAPublicKey){  //Check isserCert public key is RSA
                    if(!verifyRSASignature(subjectCert, issuerPublicKey)){  //Check RSA signature
                        System.err.println("RSA Signature verification failed.");
                        return false;
                    }
                    else{
                        System.err.println("RSA Signature is valid.");
                    }
                } 
                else{  //If not RSA, check public key with other function
                    System.err.println("Non RSA key");
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
            } 
            catch(Exception e){
                System.err.println("Signature verification failed: " + e.getMessage());
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
        catch(Exception e){
            System.err.println("Error: " + e.getMessage());
        }
        return false;
    }
    

    private static boolean validateRootCertificate(X509Certificate rootCert){
        /*
          Check the root certificate
        */
        try{
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
                    System.err.println("RSA Signature verification failed.");
                    return false;
                }
                else{
                    System.err.println("RSA Signature is valid.");
                }
            } 
            else{  //If not RSA, check public key with other function
                System.err.println("Non RSA key");
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
    
            for (int i = 0; i < certFiles.length; i++){
                certChain[i] = loadCertificate(certFiles[i], format);
                System.out.println("\nValidating Certificate: " + certChain[i].getSubjectX500Principal());
                
                if (!validateCertificate(certChain[i], certChain[i+1])){
                    System.err.println("Invalid certificate detected: " + certFiles[i]);
                    return false;
                }
            }
    
            for (int i = 0; i < certChain.length - 1; i++) {
                X509Certificate issuerCert = certChain[i];
                X509Certificate subjectCert = certChain[i + 1];
    
                System.out.println("\n Checking Chain Link:");
                System.out.println("   - Subject: " + subjectCert.getSubjectX500Principal());
                System.out.println("   - Issuer: " + subjectCert.getIssuerX500Principal());
    
                PublicKey issuerPublicKey = certChain[i+1].getPublicKey();
                if (issuerPublicKey instanceof RSAPublicKey) {
                    if (!verifyRSASignature(subjectCert, issuerPublicKey)) {
                        System.err.println("RSA Signature verification failed.");
                        return false;
                    }
                    else{
                        System.err.println("RSA Signature is valid.");
                    }
                } 
                else{
                    System.err.println("Non RSA key");
                }
    
                if (!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                    System.err.println("Error: Issuer mismatch between " +
                            subjectCert.getSubjectX500Principal() + " and " + issuerCert.getSubjectX500Principal());
                    return false;
                }
            }
    
            X509Certificate rootCert = certChain[certChain.length - 1];
            System.out.println("\n Checking Root Certificate:");
            System.out.println("   - Subject: " + rootCert.getSubjectX500Principal());
            System.out.println("   - Issuer: " + rootCert.getIssuerX500Principal());
    
            if(!validateRootCertificate(rootCert)){
                System.out.println("\n Not a root certificate!");
                return false;
            }
            if (!rootCert.getSubjectX500Principal().equals(rootCert.getIssuerX500Principal())) {
                System.err.println("Error: Issuer mismatch between " +
                rootCert.getSubjectX500Principal() + " and " + rootCert.getIssuerX500Principal());
                return false;
            }
    
            PublicKey rootPublicKey = certChain[certChain.length - 1].getPublicKey();
            if (rootPublicKey instanceof RSAPublicKey) {
                if (!verifyRSASignature(rootCert, rootPublicKey)) {
                    System.err.println("RSA Signature verification failed.");
                    return false;
                }
                else{
                    System.err.println("RSA Signature is valid.");
                }
            } 
            else{
                System.err.println("Non RSA key");
            }
    
            System.out.println("\n The certificate chain is valid!");
            return true;
    
        } 
        catch (Exception e) {
            System.err.println(" Error: " + e.getMessage());
            return false;
        }
    }
    
    

}