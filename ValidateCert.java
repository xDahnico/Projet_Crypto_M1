import java.io.*;
import java.security.*;
import java.security.cert.*;

public class ValidateCert {
    public static void main(String[] args) {
        if (args.length != 3 || !args[0].equalsIgnoreCase("-format") || !(args[1].equalsIgnoreCase("DER") || args[1].equalsIgnoreCase("PEM"))) {
            System.out.println("Usage: validate-cert -format DER|PEM <cert_file>");
            return;
        }
        
        String format = args[1];
        String certFile = args[2];
        
        try {
            X509Certificate cert = loadCertificate(certFile, format);
            validateCertificate(cert);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    private static X509Certificate loadCertificate(String certFile, String format) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(certFile)) {
            if (format.equalsIgnoreCase("DER")) {
                return (X509Certificate) cf.generateCertificate(inStream);
            } else if (format.equalsIgnoreCase("PEM")) {
                return (X509Certificate) cf.generateCertificate(inStream);
            } else {
                throw new IllegalArgumentException("Unsupported format: " + format);
            }
        }
    }
    
    private static void validateCertificate(X509Certificate cert) {
        try {
            System.out.println("Subject: " + cert.getSubjectX500Principal());
            System.out.println("Issuer: " + cert.getIssuerX500Principal());

            System.out.println("key" + cert.getPublicKey());
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey);
            System.out.println("Signature verification successful.");
            
            cert.checkValidity();
            System.out.println("Certificate is within valid date range.");
            
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && keyUsage.length > 0) {
                System.out.println("Key Usage: " + (keyUsage[5] ? "Certificate Signing" : "Not allowed"));
            }
            
            String sigAlg = cert.getSigAlgName();
            System.out.println("Signature Algorithm: " + sigAlg);
            
        } catch (CertificateExpiredException e) {
            System.err.println("Certificate is expired.");
        } catch (CertificateNotYetValidException e) {
            System.err.println("Certificate is not yet valid.");
        } catch (CertificateException e) {
            System.err.println("Certificate exception"+ e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm exception"+ e.getMessage());
        } catch (InvalidKeyException e) {
            System.err.println("Invalid key"+ e.getMessage());
        } catch (NoSuchProviderException e) {
            System.err.println("Provider exception"+ e.getMessage());
        } catch (SignatureException e) {
            System.err.println("Signature exception"+ e.getMessage());
        }
    }
}