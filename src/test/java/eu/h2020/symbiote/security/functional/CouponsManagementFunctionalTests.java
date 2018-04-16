package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.ManageCouponService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
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

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

//TODO @JT make more tests!
@TestPropertySource("/core.properties")
public class CouponsManagementFunctionalTests extends
        AbstractBTMTestSuite {

    @Autowired
    CouponIssuer couponIssuer;
    @Autowired
    CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    ManageCouponService manageCouponService;
    @Autowired
    DummyCoreAAM dummyCoreAAM;
    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;
    @LocalServerPort
    private int port;

    @Before
    public void before() {
        dummyCoreAAM.port = port;
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress + "/test/caam");
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress);
    }

    @Test
    public void getDiscreteCouponRESTSuccess() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            BTMException {

        String componentId = "testComponentId";
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/core.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "registry-core-1"));
        String loginRequest = CryptoHelper.buildJWTAcquisitionRequest(homeCredentials);

        String discreteCoupon = btmClient.getDiscreteCoupon(loginRequest);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromJWT(discreteCoupon);
        assertEquals(Coupon.Type.DISCRETE, Coupon.Type.valueOf(claimsFromToken.getTtyp()));
        assertEquals(couponValidity.toString(), claimsFromToken.getVal());
        assertTrue(issuedCouponsRepository.exists(claimsFromToken.getJti()));
        assertEquals(couponValidity, issuedCouponsRepository.findOne(claimsFromToken.getJti()).getValidity());
    }

    @Test
    public void consumeDiscreteCouponRESTSuccess() throws JWTCreationException, MalformedJWTException, WrongCredentialsException, BTMException {

        Coupon coupon = couponIssuer.getDiscreteCoupon();
        assertTrue(issuedCouponsRepository.exists(coupon.getId()));
        assertEquals(couponValidity, issuedCouponsRepository.findOne(coupon.getId()).getValidity());
        assertNotNull(coupon.getCoupon());
        boolean status = btmClient.consumeCoupon(coupon.getCoupon());
        assertTrue(status);
        assertEquals(couponValidity - 1, issuedCouponsRepository.findOne(coupon.getId()).getValidity().longValue());
    }

}
