package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.Notification;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
    private static final String PATH = "/test/caam";
    private static final String platform1Id = "dummy-platform";
    public int port;
    public boolean notify = true;
    public boolean isNotified = true;
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

    private static X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), CERTIFICATE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    @GetMapping(path = PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        aams.getAvailableAAMs().put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM("https://localhost:" + port + PATH,
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


    @PostMapping(path = PATH + "/btm" + SecurityConstants.BTM_NOTIFICATION)
    public ResponseEntity notification(@RequestBody Notification notification) {
        if (notify) {
            log.info("Coupon notified: " + notification.getCouponString());
            return new ResponseEntity(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    @PostMapping(path = PATH + "/btm" + SecurityConstants.BTM_IS_NOTIFIED)
    public ResponseEntity isNotified(@RequestBody Notification notification) {
        if (isNotified) {
            log.info("Coupon was confirmed to be notified: " + notification.getCouponString());
            return new ResponseEntity(HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

}

