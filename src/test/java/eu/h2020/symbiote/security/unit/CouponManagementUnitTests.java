package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.ManageCouponService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

@TestPropertySource("/service.properties")
public class CouponManagementUnitTests extends
        AbstractBTMTestSuite {

    @Autowired
    ManageCouponService manageCouponService;

    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;
    private AvailableAAMsCollection aams = new AvailableAAMsCollection(new HashMap<>());


    @Before
    public void before() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(manageCouponService, "btmCoreAddress", serverAddress + "/test/caam/btm");
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(manageCouponService, "btmCoreAddress", serverAddress + "/btm");
    }

    @Test
    public void getDiscreteCouponExchangeNeededSuccess() throws CertificateException, JWTCreationException, ValidationException, MalformedJWTException, InvalidArgumentsException, IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, BTMException {
        String componentId = "testComponentId";
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String loginRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);

        Coupon discreteCoupon = manageCouponService.getCoupon(loginRequest);

        assertEquals(Coupon.Type.DISCRETE, discreteCoupon.getType());
        assertEquals("100", discreteCoupon.getClaims().get("val").toString());
        assertTrue(issuedCouponsRepository.exists(discreteCoupon.getId()));
    }

    @Test
    public void getDiscreteCouponExchangeNeededFailNoConnection() {
        //TODO
    }

    //TODO
    /*@Test
    public void getDiscreteCouponExchangeNeededFailNoAgreement(){

    }*/
    @Test
    public void getDiscreteCouponNoExchangeSuccess() {
        //TODO
    }


}
