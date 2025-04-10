import java.security.cert.X509Certificate;

public class KeyUsageAndBasicConstraint {

    public static boolean verifyKeyUsage(boolean[] keyUsage, int certLevel) {
        if (keyUsage == null) {
            System.out.println("KeyUsage extension is absent.");
            return false;
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

        for (int i = 0; i < keyUsage.length && i < keyUsageLabels.length; i++) {
            System.out.println("\t" + keyUsageLabels[i] + " ➝ " + (keyUsage[i] ? "✅ Allowed" : "❌ Not Allowed"));
        }

        boolean isValid = false;
        switch (certLevel) {
            case 0:
                isValid = keyUsage.length > 0 && keyUsage[0];
                if (!isValid)
                    System.err.println("Invalid KeyUsage for Leaf Certificate: 'Digital Signature' must be enabled.");
                break;

            case -1:
                isValid = keyUsage.length > 6 && keyUsage[5] && keyUsage[6];
                if (!isValid)
                    System.err.println("Invalid KeyUsage for Root CA: 'Certificate Signing' and 'CRL Signing' must be enabled.");
                break;

            default:
                isValid = keyUsage.length > 6 && keyUsage[5] && keyUsage[6];
                if (!isValid)
                    System.err.println("Invalid KeyUsage for Intermediate CA: 'Certificate Signing' and 'CRL Signing' must be enabled.");
                break;
        }
        return isValid;
    }

    public static boolean verifyBasicConstraints(X509Certificate cert, int certLevel) {
        try {
            int basicConstraints = cert.getBasicConstraints();
            switch (certLevel) {
                case -1:
                    if (basicConstraints == 0) {
                        System.out.println("Root certificate is not a CA.");
                        return false;
                    } else {
                        System.out.println("Root CA valid, path length: " + basicConstraints);
                        return true;
                    }

            case 0:
                if (basicConstraints == -1) {
                    System.out.println("Leaf certificate is not a CA: " + basicConstraints);
                    return true;
                } else {
                    System.err.println("Error: Basic constraint " + basicConstraints + " not allowed for Leaf.");
                    return false;
                }

            default:
                if (basicConstraints < 0) {
                    System.out.println("Intermediate certificate is not a CA: " + basicConstraints);
                    return false;
                } else {
                    System.out.println("Intermediate CA path length: " + basicConstraints);
                    return true;
                }
        }
        } catch (Exception e) {
            System.err.println("Error verifying BasicConstraints: " + e.getMessage());
            return false;
        }
    }
}
