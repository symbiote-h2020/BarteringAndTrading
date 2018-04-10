package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
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
public class DummyCoreAAM {
    private static final Log log = LogFactory.getLog(DummyCoreAAM.class);
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/keystores/core.p12";
    private static final String PLATFORM_CERTIFICATE_ALIAS = "platform-1-1-c1";
    private static final String PLATFORM_CERTIFICATE_LOCATION = "./src/test/resources/keystores/platform_1.p12";
    private static final String PLATFORM_2_CERTIFICATE_ALIAS = "platform-2-1-c1";
    private static final String PLATFORM_2_CERTIFICATE_LOCATION = "./src/test/resources/keystores/platform_2.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/caam";
    private static final String platform1Id = "platform-1";
    private static final String platform2Id = "platform-2";
    public int port;
    private Certificate revokedCert;
    private AvailableAAMsCollection aams = new AvailableAAMsCollection(new HashMap<>());

    public DummyCoreAAM() throws
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
        revokedCert = new Certificate(signedCertificatePEMDataStringWriter.toString());
    }

    private static X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), CERTIFICATE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    @PostMapping(path = PATH + SecurityConstants.AAM_VALIDATE_CREDENTIALS)
    public ValidationStatus validate(@RequestHeader(SecurityConstants
            .TOKEN_HEADER_NAME) String token) {
        log.info("Validating token " + token);
        return ValidationStatus.VALID;
    }

    @GetMapping(path = PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE + "/platform/{platformIdentifier}/component/{componentIdentifier}")
    public ResponseEntity<?> getComponentCertificate(String componentIdentifier, String platformIdentifier) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        Certificate cert = new Certificate(
                CryptoHelper.convertX509ToPEM(getCertificateFromTestKeystore(
                        "keystores/core.p12",
                        "registry-core-1")));

        return new ResponseEntity<>(cert.getCertificateString(), HttpStatus.OK);
    }

    @GetMapping(path = PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    public ResponseEntity<AvailableAAMsCollection> getAvailableAAMs() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, KeyStoreException, IOException {
        if (aams.getAvailableAAMs().isEmpty()) {
            initializeAvailableAAMs();
        }
        return new ResponseEntity<>(aams, HttpStatus.OK);
    }

    public void initializeAvailableAAMs() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        clearAvailablePlatformAAMs();
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(PLATFORM_CERTIFICATE_ALIAS);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        Certificate platformCert = new Certificate(signedCertificatePEMDataStringWriter.toString());

        aams.getAvailableAAMs().put(platform1Id, new AAM("https://localhost:" + port,
                platform1Id, SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                platformCert, new HashMap<>()));

        aams.getAvailableAAMs().put("test-PlatformId", new AAM("https://localhost:" + port + "/test/paam",
                "test-PlatformId", "test-PlatformIdFriendly",
                platformCert, new HashMap<>()));
    }

    public void addPlatform2Certificate() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_2_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(PLATFORM_2_CERTIFICATE_ALIAS);
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        Certificate platformCert = new Certificate(signedCertificatePEMDataStringWriter.toString());

        aams.getAvailableAAMs().put(platform2Id, new AAM("https://localhost:" + port,
                platform2Id, SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                platformCert, new HashMap<>()));

    }

    public void changePlatformCertificate() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate("platform-1-2-c1");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(certificate);
        pemWriter.close();
        Certificate platformCert = new Certificate(signedCertificatePEMDataStringWriter.toString());

        aams.getAvailableAAMs().put(platform1Id, new AAM("https://localhost:" + port,
                platform1Id, SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                platformCert, new HashMap<>()));
    }

    public void clearAvailablePlatformAAMs() {
        this.aams.getAvailableAAMs().clear();
        aams.getAvailableAAMs().put(SecurityConstants.CORE_AAM_INSTANCE_ID, new AAM("https://localhost:" + port + PATH,
                SecurityConstants.CORE_AAM_INSTANCE_ID, SecurityConstants.CORE_AAM_FRIENDLY_NAME,
                revokedCert, new HashMap<>()));
    }


}

