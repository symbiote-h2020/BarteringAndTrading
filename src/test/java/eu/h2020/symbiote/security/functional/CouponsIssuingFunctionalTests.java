package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractBaTTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.GetCouponService;
import eu.h2020.symbiote.security.utils.DummyCoreAAM;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;

//TODO @JT make more tests!
@TestPropertySource("/core.properties")
public class CouponsIssuingFunctionalTests extends
        AbstractBaTTestSuite {

    @Autowired
    GetCouponService getCouponService;
    @Autowired
    DummyCoreAAM dummyCoreAAM;
    @Value("${btr.deployment.coupon.validity}")
    private Long couponValidity;
    @LocalServerPort
    private int port;

    @Before
    public void before() {
        ReflectionTestUtils.setField(getCouponService, "coreInterfaceAddress", serverAddress + "/test/caam");
        dummyCoreAAM.port = port;
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(getCouponService, "coreInterfaceAddress", serverAddress);
    }

    @Test
    public void getDiscreteCouponRESTSuccess() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            AAMException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException {

        String componentId = "testComponentId";
        HomeCredentials homeCredentials = new HomeCredentials(null, SecurityConstants.CORE_AAM_INSTANCE_ID, componentId, null, getPrivateKeyTestFromKeystore("keystores/core.p12",
                "registry-core-1"));
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);

        String discreteCoupon = btrClient.getDiscreteCoupon(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromJWT(discreteCoupon);
        assertEquals(Coupon.Type.DISCRETE, Coupon.Type.valueOf(claimsFromToken.getTtyp()));
        assertEquals(couponValidity.toString(), claimsFromToken.getVal());
    }
}
