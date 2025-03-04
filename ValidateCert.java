import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;

public class ValidateCert{
    public static void main(String[] args){
        if (args.length < 4 || !args[0].equalsIgnoreCase("-format") || !(args[1].equalsIgnoreCase("DER") || args[1].equalsIgnoreCase("PEM"))) {
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
        } catch (Exception e){
            System.err.println("Error: " + e.getMessage());
        }*/
    }
    
    private static X509Certificate loadCertificate(String certFile, String format) throws Exception{
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(certFile)){
            if (format.equalsIgnoreCase("DER")){
                return (X509Certificate) cf.generateCertificate(inStream);
            } else if (format.equalsIgnoreCase("PEM")){
                return (X509Certificate) cf.generateCertificate(inStream);
            } else{
                throw new IllegalArgumentException("Unsupported format: " + format);
            }
        }
    }

    private static void verifyKeyUsage(boolean[] keyUsage){
        if (keyUsage == null){
            System.out.println("KeyUsage extension is absent.");
            return;
        }
    
        String[] keyUsageLabels = {
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
    
        System.out.println("Key Usage Verification:");
        boolean isValid = true;
    
        for (int i = 0; i < keyUsage.length && i < keyUsageLabels.length; i++){
            if (keyUsage[i]){
                System.out.println("\tAllowed: " + keyUsageLabels[i]);
            } 
            else{
                System.out.println("\tNot allowed: " + keyUsageLabels[i]);
            }
        }
    
        if (keyUsage.length > 5 && keyUsage[5]){
            System.out.println("This certificate can sign other certificates.");
        } 
        else{
            System.err.println("This certificate cannot be used to sign other certificates.");
            isValid = false;
        }
    
        if (!isValid){
            System.err.println("Invalid key usage detected!");
        }
        System.out.println("");
    }
    
    private static void validateCertificate(X509Certificate cert){
        try{
            System.out.println("Subject: " + cert.getSubjectX500Principal()+"\n");
            System.out.println("Issuer: " + cert.getIssuerX500Principal()+"\n");

            System.out.println("key " + cert.getPublicKey()+"\n");
            PublicKey publicKey = cert.getPublicKey();
           
            boolean[] keyUsage = cert.getKeyUsage();
            verifyKeyUsage(keyUsage);

            byte[] signature = cert.getSignature(); 
            String signatureAlgorithm = cert.getSigAlgName(); 
            System.out.println("Signature Algorithm: " + signatureAlgorithm+"\n");

            Signature signatureInstance = Signature.getInstance(signatureAlgorithm);
            signatureInstance.initVerify(publicKey); 
            signatureInstance.update(cert.getTBSCertificate());

            if(signatureInstance.verify(signature))
                System.out.println("Certificate signature checked\n");
            else{
                System.err.println("Error : Wrong certificate signature\n");
            }
            
            cert.checkValidity();
            System.out.println("Certificate is within valid date range.\n\tFrom: "+ cert.getNotBefore()+ "\n\tUntil: " + cert.getNotAfter()+"\n");
            
        }
        catch (CertificateExpiredException e){
            System.err.println("Certificate is expired.");
        }
        catch (CertificateNotYetValidException e){
            System.err.println("Certificate is not yet valid.");
        }
        catch (CertificateException e){
            System.err.println("Certificate exception "+ e.getMessage());
        }
        catch (NoSuchAlgorithmException e){
            System.err.println("Algorithm exception "+ e.getMessage());
        }
        catch (InvalidKeyException e){
            System.err.println("Invalid key "+ e.getMessage());
        }
        catch (SignatureException e){
            System.err.println("Signature exception "+ e.getMessage());
        }
    }

    public static void validateCertificateChain(String format, String[] certFiles) {
        try {
            // Load all certificates in the given order
            X509Certificate[] certChain = new X509Certificate[certFiles.length];
            for (int i = 0; i < certFiles.length; i++) {
                certChain[i] = loadCertificate(certFiles[i], format);
                System.out.println("\n🔍 Validating Certificate: " + certChain[i].getSubjectX500Principal());
                validateCertificate(certChain[i]); // Validate each certificate individually
            }
    
            // Verify the chain step by step
            for (int i = 0; i < certChain.length - 1; i++) {
                X509Certificate issuerCert = certChain[i];
                X509Certificate subjectCert = certChain[i + 1];
    
                System.out.println("\n🔗 Checking Chain Link:");
                System.out.println("   - Subject: " + subjectCert.getSubjectX500Principal());
                System.out.println("   - Issuer: " + subjectCert.getIssuerX500Principal());
    
                // Check if the issuer of the subjectCert matches the subject of issuerCert
                if (!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                    System.err.println("❌ Error: Issuer mismatch between " +
                            subjectCert.getSubjectX500Principal() + " and " + issuerCert.getSubjectX500Principal());
                    return;
                }
    
                // Verify signature using the issuer's public key
                try {
                    subjectCert.verify(issuerCert.getPublicKey());
                    System.out.println("✅ Signature verified successfully!");
                } catch (Exception e) {
                    System.err.println("❌ Signature verification failed: " + e.getMessage());
                    return;
                }
            }
    
            System.out.println("\n✅ The certificate chain is valid!");
    
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
        }
    }
    

}