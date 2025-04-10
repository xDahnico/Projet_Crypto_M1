import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class OCSP {

    public static boolean verifyOCSP(X509Certificate cert, X509Certificate issuerCert) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            String ocspUrl = getOCSPResponderURL(cert);
            if (ocspUrl == null) {
                System.out.println("❌ No OCSP URL found in certificate.");
                return false;
            }
            System.out.println("🔍 OCSP Responder URL: " + ocspUrl);

            OCSPReq ocspRequest = generateOCSPRequest(issuerCert, cert.getSerialNumber());
            byte[] ocspResponseBytes = sendOCSPRequest(ocspUrl, ocspRequest.getEncoded());
            OCSPResp ocspResponse = new OCSPResp(ocspResponseBytes);

            if (ocspResponse.getStatus() != OCSPResp.SUCCESSFUL) {
                System.out.println("❌ OCSP request failed with status: " + ocspResponse.getStatus());
                return false;
            }

            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
            SingleResp[] responses = basicResponse.getResponses();
            CertificateStatus status = responses[0].getCertStatus();

            if (status == CertificateStatus.GOOD) {
                System.out.println("✅ Certificate is NOT revoked (OCSP).");
                return true;
            } else if (status instanceof RevokedStatus) {
                System.out.println("❌ Certificate is REVOKED (OCSP).");
                return false;
            } else {
                System.out.println("⚠️ OCSP status is UNKNOWN.");
                return false;
            }
        } catch (Exception e) {
            System.err.println("❌ OCSP verification failed: " + e.getMessage());
            return false;
        }
    }

    private static String getOCSPResponderURL(X509Certificate cert) throws IOException {
        byte[] aiaExtBytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aiaExtBytes == null) return null;

        ASN1Primitive derObj = ASN1Primitive.fromByteArray(((ASN1OctetString) ASN1OctetString.getInstance(aiaExtBytes)).getOctets());
        ASN1Sequence aiaSeq = ASN1Sequence.getInstance(derObj);

        for (ASN1Encodable element : aiaSeq) {
            AccessDescription ad = AccessDescription.getInstance(element);
            if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                GeneralName gn = ad.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return DERIA5String.getInstance(gn.getName()).getString();
                }
            }
        }
        return null;
    }

    private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        CertificateID certId = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert),
                serialNumber
        );

        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);
        return builder.build();
    }

    private static byte[] sendOCSPRequest(String ocspUrl, byte[] requestData) throws IOException {
        URL url = new URL(ocspUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setRequestProperty("Accept", "application/ocsp-response");
        con.setDoOutput(true);

        try (OutputStream os = con.getOutputStream()) {
            os.write(requestData);
            os.flush();
        }

        if (con.getResponseCode() != 200) {
            throw new IOException("OCSP request failed with HTTP code: " + con.getResponseCode());
        }

        try (InputStream is = con.getInputStream()) {
            return is.readAllBytes();
        }
    }   
}
