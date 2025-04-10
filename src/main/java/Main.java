import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
    public static void main(String[] args) {
        try {
            if (args.length < 4 || !args[0].equalsIgnoreCase("-format") ||
                !(args[1].equalsIgnoreCase("DER") || args[1].equalsIgnoreCase("PEM"))) {
                System.out.println("Usage: validate-cert-chain -format DER|PEM <root_cert> <inter_cert> <leaf_cert>");
                return;
            }

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            String format = args[1];
            String[] certFiles = Arrays.copyOfRange(args, 2, args.length);
            ValidateCertificate.validateCertificateChain(format, certFiles);
        } catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
        }
    }
}
