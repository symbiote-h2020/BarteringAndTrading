package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.security.services.ManageCouponService;
import eu.h2020.symbiote.security.utils.DummyPlatformBTM;
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

import static eu.h2020.symbiote.security.services.helpers.CouponIssuer.buildCouponJWT;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@TestPropertySource("/service.properties")
public class CouponManagementUnitTests extends
        AbstractBTMTestSuite {

    @Autowired
    ManageCouponService manageCouponService;
    @Autowired
    DummyPlatformBTM dummyPlatformBTM;

    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;
    private String componentId = "testComponentId";


    @Before
    public void before() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress + "/test/caam");
        ReflectionTestUtils.setField(manageCouponService, "btmCoreAddress", serverAddress + "/test/caam/btm");
        dummyPlatformBTM.exchangeState = DummyPlatformBTM.ExchangeState.OK;
        dummyCoreAAMAndBTM.notify = true;
        dummyCoreAAMAndBTM.isNotified = true;
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress);
        ReflectionTestUtils.setField(manageCouponService, "btmCoreAddress", serverAddress + "/btm");
    }

    @Test
    public void getDiscreteCouponExchangeNeededSuccess() throws CertificateException, JWTCreationException, ValidationException, MalformedJWTException, InvalidArgumentsException, IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException, BTMException {
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);

        Coupon discreteCoupon = manageCouponService.getCoupon(couponRequest);

        assertEquals(Coupon.Type.DISCRETE, discreteCoupon.getType());
        assertEquals("100", discreteCoupon.getClaims().get("val").toString());
        assertTrue(issuedCouponsRepository.exists(discreteCoupon.getId()));
    }

    @Test(expected = BTMException.class)
    public void getDiscreteCouponExchangeNeededFailNoCoreConnection() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress + "/test/caam/wrong");
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);

        manageCouponService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getDiscreteCouponExchangeNeededFailCoreNotNotified() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        dummyCoreAAMAndBTM.notify = false;
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);

        manageCouponService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getDiscreteCouponExchangeNeededFailNoFederatedPlatformConnection() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        dummyPlatformBTM.exchangeState = DummyPlatformBTM.ExchangeState.NO_CONNECTION;
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);
        manageCouponService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getDiscreteCouponExchangeNeededFailFederatedPlatformRefusedExchange() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        // make issuedCoupons not empty
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        IssuedCoupon issuedCoupon = new IssuedCoupon(coupon);
        issuedCoupon.setStatus(IssuedCoupon.Status.CONSUMED);
        issuedCouponsRepository.save(issuedCoupon);

        dummyPlatformBTM.exchangeState = DummyPlatformBTM.ExchangeState.REFUSED;
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);
        manageCouponService.getCoupon(couponRequest);
    }

    @Test(expected = InvalidArgumentsException.class)
    public void getDiscreteCouponFailWrongRequest() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        dummyPlatformBTM.exchangeState = DummyPlatformBTM.ExchangeState.REFUSED;
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, "");
        try {
            manageCouponService.getCoupon(couponRequest);
            fail();
        } catch (InvalidArgumentsException ignored) {
        }
        couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, null);
        manageCouponService.getCoupon(couponRequest);
    }

    @Test(expected = ValidationException.class)
    public void getDiscreteCouponExchangeNeededFailNoPlatformInAvailableAAMs() throws
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        dummyPlatformBTM.exchangeState = DummyPlatformBTM.ExchangeState.REFUSED;
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, "notAvailablePlatform");
        manageCouponService.getCoupon(couponRequest);
    }

    @Test
    public void getDiscreteCouponNoExchangeSuccess() throws
            ValidationException,
            CertificateException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            IOException,
            MalformedJWTException,
            InvalidArgumentsException,
            BTMException,
            JWTCreationException {
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        issuedCouponsRepository.save(new IssuedCoupon(coupon));
        assertEquals(1, issuedCouponsRepository.count());
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/service_btm.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "btm"));
        String couponRequest = CryptoHelper.buildCouponAcquisitionRequest(homeCredentials, dummyPlatformId);
        Coupon acquiredCoupon = manageCouponService.getCoupon(couponRequest);
        assertEquals(1, issuedCouponsRepository.count());
        assertEquals(coupon.getCoupon(), acquiredCoupon.getCoupon());
        assertEquals(coupon.getId(), acquiredCoupon.getId());
        assertEquals(coupon.getType(), acquiredCoupon.getType());
        assertEquals(coupon.getClaims().get("val"), acquiredCoupon.getClaims().get("val"));
    }

    @Test
    public void exchangeCouponSuccess() throws
            ValidationException,
            JWTCreationException,
            BTMException {
        //check if repo is empty
        assertEquals(0, issuedCouponsRepository.count());
        //get any coupon for exchange
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        //exchange coupon
        Coupon exchangedCoupon = manageCouponService.exchangeCoupon(coupon.getCoupon());
        // booth coupons should be in repository
        assertEquals(2, issuedCouponsRepository.count());
        assertTrue(issuedCouponsRepository.exists(exchangedCoupon.getId()));
        assertTrue(issuedCouponsRepository.exists(coupon.getId()));
    }

    @Test(expected = BTMException.class)
    public void exchangeCouponFailNoCoreConnection() throws
            ValidationException,
            JWTCreationException,
            BTMException {
        ReflectionTestUtils.setField(manageCouponService, "btmCoreAddress", serverAddress + "/test/caam/btm/wrong");
        //check if repo is empty
        assertEquals(0, issuedCouponsRepository.count());
        //get any coupon for exchange
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        //exchange coupon
        manageCouponService.exchangeCoupon(coupon.getCoupon());
    }

    @Test(expected = BTMException.class)
    public void exchangeCouponFailNoCoreNotification() throws
            ValidationException,
            JWTCreationException,
            BTMException {
        dummyCoreAAMAndBTM.isNotified = false;
        //check if repo is empty
        assertEquals(0, issuedCouponsRepository.count());
        //get any coupon for exchange
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        //exchange coupon
        manageCouponService.exchangeCoupon(coupon.getCoupon());

    }

}
