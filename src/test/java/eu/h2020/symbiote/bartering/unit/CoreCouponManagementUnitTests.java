package eu.h2020.symbiote.bartering.unit;

import eu.h2020.symbiote.bartering.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.bartering.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.bartering.services.helpers.CouponIssuer;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@TestPropertySource("/core.properties")
public class CoreCouponManagementUnitTests extends AbstractCoreBTMTestSuite {

    private static final String KEY_STORE_NAME = "keystores/dummy_service_btm.p12";
    private static final String KEY_STORE_PATH = "./src/test/resources/keystores/dummy_service_btm.p12";
    private static final String CERTIFICATE_ALIAS = "btm";
    private static final String KEY_STORE_PASSWORD = "1234567";


    private KeyPair btmKeyPair;

    @Before
    public void setUp() throws
            Exception {
        super.setUp();
        ReflectionTestUtils.setField(issuedCouponsRegistryManagementService, "coreInterfaceAddress", serverAddress + "/test/caam");
        PrivateKey privateKey = getPrivateKeyTestFromKeystore(KEY_STORE_NAME, KEY_STORE_PASSWORD, CERTIFICATE_ALIAS);
        X509Certificate certificate = getCertificateFromTestKeystore(KEY_STORE_PATH, KEY_STORE_PASSWORD, CERTIFICATE_ALIAS);
        this.btmKeyPair = new KeyPair(certificate.getPublicKey(), privateKey);
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(issuedCouponsRegistryManagementService, "coreInterfaceAddress", serverAddress);
    }

    @Test
    public void registerCouponSuccess() throws
            MalformedJWTException,
            ValidationException,
            CertificateException,
            AAMException,
            BTMException,
            IOException {
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(issuedCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(issuedCouponsRegistryManagementService.registerCoupon(couponString));
        //check the DB
        assertTrue(issuedCouponsRegistry.exists(registeredCouponId));
        IssuedCoupon issuedCoupon = issuedCouponsRegistry.findOne(registeredCouponId);
        assertEquals(couponString, issuedCoupon.getCouponString());
        assertEquals(0, issuedCoupon.getFirstUseTimestamp());
        assertEquals(0, issuedCoupon.getLastConsumptionTimestamp());
        assertEquals(0, issuedCoupon.getUsagesCounter());
        assertEquals(Coupon.Type.DISCRETE, issuedCoupon.getType());
        assertEquals(CouponValidationStatus.VALID, issuedCoupon.getStatus());
    }

    @Test(expected = AAMException.class)
    public void registerCouponFailCoreAAMNotAvailable() throws
            MalformedJWTException,
            ValidationException,
            CertificateException,
            AAMException,
            BTMException,
            IOException {
        ReflectionTestUtils.setField(issuedCouponsRegistryManagementService, "coreInterfaceAddress", "wrongAddress");
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(issuedCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(couponString);
    }

    @Test(expected = ValidationException.class)
    public void registerCouponFailMalformedCoupon() throws
            CertificateException,
            AAMException,
            BTMException,
            IOException,
            ValidationException,
            MalformedJWTException {
        //generate coupon using btm cert
        String couponString = "malformedCoupon";
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(couponString);
    }

    @Test(expected = ValidationException.class)
    public void registerCouponFailMismatchOfComponentKeys() throws
            CertificateException,
            AAMException,
            BTMException,
            IOException,
            ValidationException,
            MalformedJWTException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //generate coupon using random keys
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(issuedCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(couponString);
    }

    @Test(expected = ValidationException.class)
    public void registerCouponFailWrongValValue() throws
            CertificateException,
            AAMException,
            BTMException,
            IOException,
            ValidationException,
            MalformedJWTException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //generate coupon using random keys
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                -5,
                "test",
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(issuedCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(couponString);
    }

    @Test(expected = BTMException.class)
    public void registerCouponFailAlreadyRegistered() throws
            CertificateException,
            AAMException,
            BTMException,
            IOException,
            ValidationException,
            MalformedJWTException {
        //generate coupon using random keys
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(issuedCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(issuedCouponsRegistryManagementService.registerCoupon(couponString));
        //check if coupon in db
        assertTrue(issuedCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(couponString);
    }

    @Test
    public void consumeDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCouponsRegistry.save(issuedCoupon);
        //consume Coupon
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        issuedCoupon = issuedCouponsRegistry.findOne(issuedCoupon.getId());
        assertEquals(1, issuedCoupon.getUsagesCounter());
        assertNotEquals(0, issuedCoupon.getFirstUseTimestamp());
        assertNotEquals(0, issuedCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, issuedCoupon.getStatus());
        //consume it again to change its status
        couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        issuedCoupon = issuedCouponsRegistry.findOne(issuedCoupon.getId());
        assertEquals(2, issuedCoupon.getUsagesCounter());
        assertNotEquals(issuedCoupon.getFirstUseTimestamp(), issuedCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, issuedCoupon.getStatus());
    }

    @Test
    public void consumePeriodicCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.PERIODIC,
                10000,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCouponsRegistry.save(issuedCoupon);
        //consume Coupon
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        issuedCoupon = issuedCouponsRegistry.findOne(issuedCoupon.getId());
        assertEquals(1, issuedCoupon.getUsagesCounter());
        assertNotEquals(0, issuedCoupon.getFirstUseTimestamp());
        assertNotEquals(0, issuedCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, issuedCoupon.getStatus());
        //consume it again
        couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        issuedCoupon = issuedCouponsRegistry.findOne(issuedCoupon.getId());
        assertEquals(2, issuedCoupon.getUsagesCounter());
        assertNotEquals(issuedCoupon.getFirstUseTimestamp(), issuedCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, issuedCoupon.getStatus());
    }

    @Test
    public void consumeCouponFailCouponNotValid() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.PERIODIC,
                10000,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon);
        //consume Coupon
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidationStatus);
        //check if coupon did not changed in db
        IssuedCoupon issuedCouponDB = issuedCouponsRegistry.findOne(issuedCoupon.getId());
        assertEquals(issuedCoupon.getUsagesCounter(), issuedCouponDB.getUsagesCounter());
        assertEquals(issuedCoupon.getFirstUseTimestamp(), issuedCouponDB.getFirstUseTimestamp());
        assertEquals(issuedCoupon.getLastConsumptionTimestamp(), issuedCouponDB.getLastConsumptionTimestamp());
        assertEquals(issuedCoupon.getStatus(), issuedCouponDB.getStatus());
        assertEquals(issuedCoupon.getType(), issuedCouponDB.getType());
        assertEquals(issuedCoupon.getMaximumAllowedUsage(), issuedCouponDB.getMaximumAllowedUsage());
        assertEquals(issuedCoupon.getCouponString(), issuedCouponDB.getCouponString());
        assertEquals(issuedCoupon.getIssuer(), issuedCouponDB.getIssuer());
    }

    @Test(expected = MalformedJWTException.class)
    public void consumeCouponFailMalformedCoupon() throws
            MalformedJWTException {
        String couponString = "MalformedCoupon";
        issuedCouponsRegistryManagementService.consumeCoupon(couponString);
    }

    @Test
    public void validateDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                10,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(10, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
        //usage added
        issuedCoupon.setUsagesCounter(1);
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(9, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void validatePeriodicCouponSuccess() throws
            MalformedJWTException,
            ValidationException,
            InterruptedException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.PERIODIC,
                10000,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(10000, couponValidity.getRemainingTime());
        //usage added
        issuedCoupon.setFirstUseTimestamp(new Date().getTime());
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        Thread.sleep(1);
        couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertTrue(couponValidity.getRemainingTime() < 10000);
    }

    @Test
    public void validatePeriodicCouponFailValidityEnded() throws
            MalformedJWTException,
            ValidationException,
            InterruptedException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.PERIODIC,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCouponsRegistry.save(issuedCoupon);
        //usage added
        issuedCoupon.setFirstUseTimestamp(new Date().getTime());
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        Thread.sleep(1);
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void validateDiscreteCouponFailConsumedCoupon() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.PERIODIC,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void validateCouponFailNotRegistered() throws
            MalformedJWTException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.COUPON_NOT_REGISTERED, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void validateCouponFailCouponRevoked() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db as revoked
        IssuedCoupon issuedCoupon = new IssuedCoupon(couponString);
        issuedCoupon.setStatus(CouponValidationStatus.REVOKED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.REVOKED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test(expected = MalformedJWTException.class)
    public void validateCouponFailMalformedCoupon() throws
            MalformedJWTException {
        String couponString = "MalformedCoupon";
        issuedCouponsRegistryManagementService.isCouponValid(couponString);
    }

    @Test
    public void validateCouponFailCouponMismatch() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());

        String forgedCouponString = CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                1,
                "forgedIssuer",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());


        //put it in repo with changed couponString
        IssuedCoupon issuedCoupon1 = new IssuedCoupon(couponString);
        ReflectionTestUtils.setField(issuedCoupon1, "couponString", forgedCouponString);
        issuedCouponsRegistry.save(issuedCoupon1);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.DB_MISMATCH, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void cleanupConsumedCouponsSuccess() throws
            MalformedJWTException,
            ValidationException {
        long cleanupTimestamp = 100000;
        //generate some coupons and save them in repo
        String coupon1 = CouponIssuer.buildCouponJWT(Coupon.Type.DISCRETE, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon2 = CouponIssuer.buildCouponJWT(Coupon.Type.DISCRETE, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon3 = CouponIssuer.buildCouponJWT(Coupon.Type.PERIODIC, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon4 = CouponIssuer.buildCouponJWT(Coupon.Type.PERIODIC, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon5 = CouponIssuer.buildCouponJWT(Coupon.Type.PERIODIC, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        IssuedCoupon issuedCoupon1 = new IssuedCoupon(coupon1);
        issuedCoupon1.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        issuedCoupon1.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon1);
        IssuedCoupon issuedCoupon2 = new IssuedCoupon(coupon2);
        issuedCoupon2.setLastConsumptionTimestamp(cleanupTimestamp + 1);
        issuedCoupon2.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon2);
        IssuedCoupon issuedCoupon3 = new IssuedCoupon(coupon3);
        issuedCoupon3.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        issuedCoupon3.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon3);
        IssuedCoupon issuedCoupon4 = new IssuedCoupon(coupon4);
        issuedCoupon4.setLastConsumptionTimestamp(cleanupTimestamp + 1);
        issuedCoupon4.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        issuedCouponsRegistry.save(issuedCoupon4);
        IssuedCoupon issuedCoupon5 = new IssuedCoupon(coupon5);
        issuedCoupon5.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        issuedCoupon5.setStatus(CouponValidationStatus.VALID);
        issuedCouponsRegistry.save(issuedCoupon5);

        int cleanedCoupons = issuedCouponsRegistryManagementService.cleanupConsumedCoupons(cleanupTimestamp);
        //checking response
        assertEquals(2, cleanedCoupons);
        //checking db
        assertEquals(3, issuedCouponsRegistry.count());
        assertTrue(issuedCouponsRegistry.exists(issuedCoupon2.getId()));
        assertTrue(issuedCouponsRegistry.exists(issuedCoupon4.getId()));
        assertTrue(issuedCouponsRegistry.exists(issuedCoupon5.getId()));
        assertFalse(issuedCouponsRegistry.exists(issuedCoupon1.getId()));
        assertFalse(issuedCouponsRegistry.exists(issuedCoupon3.getId()));
    }


}
