import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateLoader {

    public static X509Certificate loadCertificate(String certPath, String format) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream certInputStream = new FileInputStream(certPath)) {
            return (X509Certificate) factory.generateCertificate(certInputStream);
        }
    }
}
