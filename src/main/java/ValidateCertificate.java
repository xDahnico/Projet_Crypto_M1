import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.interfaces.ECPublicKey;

public class ValidateCertificate {

    public static boolean validateCertificate(X509Certificate subjectCert, X509Certificate issuerCert, int certLevel) {
        try {
            System.out.println("\n- Subject: " + subjectCert.getSubjectX500Principal());
            System.out.println("- Issuer: " + issuerCert.getSubjectX500Principal());

            if (!subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                System.err.println("Error: Issuer mismatch between " +
                    subjectCert.getIssuerX500Principal() + " and " + issuerCert.getSubjectX500Principal());
                return false;
            }

            PublicKey issuerPublicKey = issuerCert.getPublicKey();
            try {
                if (issuerPublicKey instanceof RSAPublicKey) {
                    if (!SignatureVerification.verifyRSASignature(subjectCert, issuerPublicKey)) {
                        return false;
                    }
                } else if (issuerPublicKey instanceof ECPublicKey) {
                    if (!SignatureVerification.verifyECDSASignature(subjectCert, issuerPublicKey)) {
                        return false;
                    }
                }
                
            } catch (Exception ex) {
                System.err.println("Error verifying signature: " + ex.getMessage());
                return false;
            }

            if (!KeyUsageAndBasicConstraint.verifyKeyUsage(issuerCert.getKeyUsage(), certLevel)) {
                return false;
            }
            
            if (!KeyUsageAndBasicConstraint.verifyBasicConstraints(subjectCert, certLevel)) {
                return false;
            }
            

            subjectCert.checkValidity();
            System.out.println("\nCertificate is within valid date range.\n\tFrom: " + subjectCert.getNotBefore() + "\n\tUntil: " + subjectCert.getNotAfter() + "\n");

            if (CRL.isCertificateRevoked(subjectCert)) {
                return false;
            }

            if (!OCSP.verifyOCSP(subjectCert, issuerCert)) {
                return false;
            }

            System.out.println("Certificate validation successful.\n\n");
            return true;
        } catch (CertificateExpiredException e) {
            System.err.println("Certificate is expired.");
        } catch (CertificateNotYetValidException e) {
            System.err.println("Certificate is not yet valid.");
        } catch (Exception e) {
            System.err.println("General error validating certificate: " + e.getMessage());
        }
        return false;
    }

    public static boolean validateRootCertificate(X509Certificate rootCert) {
        try {
            System.out.println("\n- Subject: " + rootCert.getSubjectX500Principal());
            System.out.println("- Issuer: " + rootCert.getIssuerX500Principal() + "\n");

            if (!rootCert.getSubjectX500Principal().equals(rootCert.getIssuerX500Principal())) {
                System.err.println("Error: Issuer mismatch between " +
                    rootCert.getIssuerX500Principal() + " and " + rootCert.getSubjectX500Principal());
                return false;
            }

            try {
                rootCert.verify(rootCert.getPublicKey());
                System.out.println("Root Certificate is correctly self-signed.");
            } catch (Exception e) {
                System.err.println("Root certificate signature verification failed: " + e.getMessage());
                return false;
            }

            if (!KeyUsageAndBasicConstraint.verifyKeyUsage(rootCert.getKeyUsage(), -1)) {
                System.err.println("Key usage is not correct, certificate not allowed to sign other certificates.");
                return false;
            }

            PublicKey rootPublicKey = rootCert.getPublicKey();
            try {
                if (rootPublicKey instanceof RSAPublicKey) {
                    if (!SignatureVerification.verifyRSASignature(rootCert, rootPublicKey)) {
                        System.err.println("RSA Signature verification failed.");
                        return false;
                    }
                } else if (rootPublicKey instanceof ECPublicKey) {
                    if (!SignatureVerification.verifyECDSASignature(rootCert, rootPublicKey)) {
                        System.err.println("ECDSA Signature verification failed.");
                        return false;
                    }
                }
            } catch (Exception ex) {
                System.err.println("Error verifying signature: " + ex.getMessage());
                return false;
            }

            if (!KeyUsageAndBasicConstraint.verifyBasicConstraints(rootCert, -1)) {
                System.err.println("Error: Basic Constraints not valid for this certificate level.");
                return false;
            }

            rootCert.checkValidity();
            System.out.println("\nCertificate is within valid date range.\n\tFrom: " + rootCert.getNotBefore() + "\n\tUntil: " + rootCert.getNotAfter() + "\n");

            if (CRL.isCertificateRevoked(rootCert)) {
                return false;
            }

            System.out.println("Root certificate valid!\n");
            return true;
        } catch (CertificateExpiredException e) {
            System.err.println("Certificate is expired.");
        } catch (CertificateNotYetValidException e) {
            System.err.println("Certificate is not yet valid.");
        } catch (Exception e) {
            System.err.println("General error validating root certificate: " + e.getMessage());
        }
        return false;
    }

    public static boolean validateCertificateChain(String format, String[] certFiles) {
        try {
            X509Certificate[] certChain = new X509Certificate[certFiles.length];

            for (int i = 0; i < certFiles.length - 1; i++) {
                certChain[i] = CertificateLoader.loadCertificate(certFiles[i], format);
                X509Certificate issuerCert = CertificateLoader.loadCertificate(certFiles[i + 1], format);
                if (!validateCertificate(certChain[i], issuerCert, i))
                    return false;
            }

            X509Certificate rootCert = CertificateLoader.loadCertificate(certFiles[certFiles.length - 1], format);
            if (!validateRootCertificate(rootCert)) {
                System.out.println("\n Not a root certificate!");
                return false;
            }

            System.out.println("\n\n\nThe certificate chain is valid!");
            return true;
        } catch (Exception e) {
            System.err.println(" Error: " + e.getMessage());
            return false;
        }
    }
}
