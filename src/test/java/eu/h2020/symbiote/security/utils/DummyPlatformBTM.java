package eu.h2020.symbiote.security.utils;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import static eu.h2020.symbiote.security.services.helpers.CouponIssuer.buildCouponJWT;


/**
 * Dummy REST service mimicking exposed AAM features required by SymbIoTe users and reachable via CoreInterface in
 * the Core and Interworking Interfaces on Platforms' side.
 *
 * @author Piotr Kicki (PSNC)
 */
@RestController
public class DummyPlatformBTM {
    private static final Log log = LogFactory.getLog(DummyPlatformBTM.class);
    private static final String BTM_CERTIFICATE_ALIAS = "btm";
    private static final String PLATFORM_CERTIFICATE_LOCATION = "./src/test/resources/keystores/dummy_service_btm.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String PATH = "/test/platform/btm";
    private static final String platformId = "dummy-platform";
    public String receivedCouponIssuer = platformId;
    public int port;
    private KeyStore ks;
    private Key key;
    private Certificate coreCert;
    private AvailableAAMsCollection aams = new AvailableAAMsCollection(new HashMap<>());

    public DummyPlatformBTM() throws NoSuchProviderException, KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(PLATFORM_CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());
        this.key = ks.getKey(BTM_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());
    }

    @PostMapping(path = PATH + SecurityConstants.BTM_GET_COUPON)
    public ResponseEntity<String> exchangeCoupon(@RequestBody CouponRequest couponRequest) throws
            KeyStoreException {
        Map<String, String> attributes = new HashMap<>();
        String couponString = buildCouponJWT(
                attributes,
                couponRequest.getCouponType(),
                100,
                receivedCouponIssuer,
                ks.getCertificate(BTM_CERTIFICATE_ALIAS).getPublicKey(),
                (PrivateKey) key
        );
        return new ResponseEntity<>(couponString, HttpStatus.OK);
    }


}

