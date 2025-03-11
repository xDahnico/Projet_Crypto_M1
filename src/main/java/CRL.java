import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;


public class CRL {

    public static boolean isCertificateRevoked(X509Certificate cert) {
        try {
            String crlUrl = getCRLDistributionPoint(cert);
            if (crlUrl == null) {
                System.err.println("❌ No CRL Distribution Point found.");
                return false;
            }
            System.out.println("🔍 CRL URL: " + crlUrl);

            String crlFileName = "CRL/" + crlUrl.substring(crlUrl.lastIndexOf('/') + 1);
            File crlFile = new File(crlFileName);
            if (!crlFile.exists() || isCRLExpired(crlFile)) {
                System.out.println("⚠️ CRL is missing or outdated. Downloading...");
                downloadCRL(crlUrl, crlFileName);
            } else {
                System.out.println("✅ Using local CRL: " + crlFileName);
            }

            X509CRL crl = loadCRL(crlFile);
            if (crl == null) {
                System.err.println("❌ Failed to load CRL.");
                return false;
            }

            BigInteger serialNumber = cert.getSerialNumber();
            X509CRLEntry revokedEntry = crl.getRevokedCertificate(serialNumber);
            if (revokedEntry != null) {
                System.err.println("❌ Certificate is revoked! Serial: " + serialNumber);
                return true;
            } else {
                System.out.println("✅ Certificate is NOT revoked.");
                return false;
            }

        } catch (Exception e) {
            System.err.println("Error checking certificate revocation: " + e.getMessage());
            return false;
        }
    }

    private static String getCRLDistributionPoint(X509Certificate cert) throws Exception {
        byte[] crlDistributionPoints = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlDistributionPoints == null) return null;

        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString) ASN1Primitive.fromByteArray(crlDistributionPoints)).getOctets()));
        ASN1Primitive derObject = asn1InputStream.readObject();
        asn1InputStream.close();

        CRLDistPoint distPoint = CRLDistPoint.getInstance(derObject);
        if (distPoint == null) return null;

        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpName = dp.getDistributionPoint();
            if (dpName != null && dpName.getType() == DistributionPointName.FULL_NAME) {
                GeneralNames names = GeneralNames.getInstance(dpName.getName());
                for (GeneralName name : names.getNames()) {
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        return name.getName().toString();
                    }
                }
            }
        }
        return null;
    }

    private static boolean isCRLExpired(File crlFile) {
        try {
            X509CRL crl = loadCRL(crlFile);
            if (crl == null) return true;
            return crl.getNextUpdate().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    private static void downloadCRL(String crlUrl, String savePath) throws IOException {
        try (InputStream in = new URL(crlUrl).openStream();
             FileOutputStream out = new FileOutputStream(savePath)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            System.out.println("✅ CRL downloaded: " + savePath);
        }
    }

    private static X509CRL loadCRL(File crlFile) {
        try (InputStream in = new FileInputStream(crlFile)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(in);
        } catch (Exception e) {
            System.err.println("Error loading CRL: " + e.getMessage());
            return null;
        }
    }
}
