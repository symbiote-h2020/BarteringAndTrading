package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;


/**
 * Dummy REST service mimicking exposed AAM features required by SymbIoTe users and reachable via CoreInterface in
 * the Core and Interworking Interfaces on Platforms' side.
 *
 * @author Piotr Kicki (PSNC)
 */
@RestController
public class DummyCoreAAMAndBTM {
    private static final Log log = LogFactory.getLog(DummyCoreAAMAndBTM.class);
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/keystores/core.p12";
    private static final String PLATFORM_CERTIFICATE_ALIAS = "platform";
    private static final String PLATFORM_CERTIFICATE_LOCATION = "./src/test/resources/keystores/dummy_service_btm.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String AAM_PATH = "/test/caam";
    private static final String BTM_PATH = "/test/btm";
    private static final String platform1Id = "dummy-platform";
    public int port;
    public HttpStatus registrationStatus = HttpStatus.OK;
    public CouponValidationStatus couponValidationStatus = CouponValidationStatus.VALID;
    private Certificate coreCert;
    private AvailableAAMsCollection aams = new AvailableAAMsCollection(new HashMap<>());

    public DummyCoreAAMAndBTM() throws
            CertificateException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("core-1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        coreCert = new Certificate(signedCertificatePEMDataStringWriter.toString());
    }

    @GetMapping(path = AAM_PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        aams.getAvailableAAMs().put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM("https://localhost:" + port + AAM_PATH,
                SecurityConstants.CORE_AAM_INSTANCE_ID, SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                coreCert, new HashMap<>()));
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(PLATFORM_CERTIFICATE_ALIAS);
        Certificate platformCert = new Certificate(CryptoHelper.convertX509ToPEM(certificate));

        aams.getAvailableAAMs().put(platform1Id, new AAM("https://localhost:" + port + "/test/platform",
                platform1Id, platform1Id,
                platformCert, new HashMap<>()));

        return new ResponseEntity<>(aams, HttpStatus.OK);
    }

    @GetMapping(path = AAM_PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE + "/platform/{platformIdentifier}/component/{componentIdentifier}")
    public String getBTMCertificate() throws NoSuchProviderException, KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("btm");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }

    @PostMapping(path = BTM_PATH + SecurityConstants.BTM_REGISTER_COUPON)
    public ResponseEntity<String> registerCoupon(String couponString) {
        return new ResponseEntity<>(registrationStatus);
    }

    @PostMapping(path = BTM_PATH + SecurityConstants.BTM_IS_COUPON_VALID)
    public CouponValidity isCouponValid(String couponString) {
        return new CouponValidity(couponValidationStatus, Coupon.Type.DISCRETE, 10, 0);
    }



}

