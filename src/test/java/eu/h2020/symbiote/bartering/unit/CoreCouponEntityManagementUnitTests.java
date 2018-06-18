package eu.h2020.symbiote.bartering.unit;

import eu.h2020.symbiote.bartering.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
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
public class CoreCouponEntityManagementUnitTests extends AbstractCoreBTMTestSuite {

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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(issuedCouponsRegistryManagementService.registerCoupon(couponString));
        //check the DB
        assertTrue(globalCouponsRegistry.exists(registeredCouponId));
        AccountingCoupon accountingCoupon = globalCouponsRegistry.findOne(registeredCouponId);
        assertEquals(couponString, accountingCoupon.getCouponString());
        assertEquals(0, accountingCoupon.getFirstUseTimestamp());
        assertEquals(0, accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(0, accountingCoupon.getUsagesCounter());
        assertEquals(Coupon.Type.DISCRETE, accountingCoupon.getType());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                -5,
                "test",
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(issuedCouponsRegistryManagementService.registerCoupon(couponString));
        //check if coupon in db
        assertTrue(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(couponString);
    }

    @Test
    public void consumeDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWS(Coupon.Type.DISCRETE,
                2,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //consume CouponEntity
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        accountingCoupon = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(1, accountingCoupon.getUsagesCounter());
        assertNotEquals(0, accountingCoupon.getFirstUseTimestamp());
        assertNotEquals(0, accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
        //consume it again to change its status
        couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        accountingCoupon = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(2, accountingCoupon.getUsagesCounter());
        assertNotEquals(accountingCoupon.getFirstUseTimestamp(), accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, accountingCoupon.getStatus());
    }

    @Test
    public void consumePeriodicCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.PERIODIC,
                10000,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //consume CouponEntity
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        accountingCoupon = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(1, accountingCoupon.getUsagesCounter());
        assertNotEquals(0, accountingCoupon.getFirstUseTimestamp());
        assertNotEquals(0, accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
        //consume it again
        couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        accountingCoupon = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(2, accountingCoupon.getUsagesCounter());
        assertNotEquals(accountingCoupon.getFirstUseTimestamp(), accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
    }

    @Test
    public void consumeCouponFailCouponNotValid() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.PERIODIC,
                10000,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        accountingCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
        //consume CouponEntity
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidationStatus);
        //check if coupon did not changed in db
        AccountingCoupon accountingCouponDB = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(accountingCoupon.getUsagesCounter(), accountingCouponDB.getUsagesCounter());
        assertEquals(accountingCoupon.getFirstUseTimestamp(), accountingCouponDB.getFirstUseTimestamp());
        assertEquals(accountingCoupon.getLastConsumptionTimestamp(), accountingCouponDB.getLastConsumptionTimestamp());
        assertEquals(accountingCoupon.getStatus(), accountingCouponDB.getStatus());
        assertEquals(accountingCoupon.getType(), accountingCouponDB.getType());
        assertEquals(accountingCoupon.getMaximumAllowedUsage(), accountingCouponDB.getMaximumAllowedUsage());
        assertEquals(accountingCoupon.getCouponString(), accountingCouponDB.getCouponString());
        assertEquals(accountingCoupon.getIssuer(), accountingCouponDB.getIssuer());
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                10,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(10, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
        //usage added
        accountingCoupon.setUsagesCounter(1);
        globalCouponsRegistry.save(accountingCoupon);
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.PERIODIC,
                10000,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(10000, couponValidity.getRemainingTime());
        //usage added
        accountingCoupon.setFirstUseTimestamp(new Date().getTime());
        globalCouponsRegistry.save(accountingCoupon);
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.PERIODIC,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //usage added
        accountingCoupon.setFirstUseTimestamp(new Date().getTime());
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        Thread.sleep(100);
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.PERIODIC,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        accountingCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
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
        String couponString = CouponIssuer.buildCouponJWS(
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());
        //save coupon in db as revoked
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        accountingCoupon.setStatus(CouponValidationStatus.REVOKED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
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
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                1,
                "test",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());

        String forgedCouponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                1,
                "forgedIssuer",
                FEDERATION_ID,
                btmKeyPair.getPublic(),
                btmKeyPair.getPrivate());


        //put it in repo with changed couponString
        AccountingCoupon accountingCoupon1 = new AccountingCoupon(couponString);
        ReflectionTestUtils.setField(accountingCoupon1, "couponString", forgedCouponString);
        globalCouponsRegistry.save(accountingCoupon1);
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
        String coupon1 = CouponIssuer.buildCouponJWS(Coupon.Type.DISCRETE, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon2 = CouponIssuer.buildCouponJWS(Coupon.Type.DISCRETE, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon3 = CouponIssuer.buildCouponJWS(Coupon.Type.PERIODIC, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon4 = CouponIssuer.buildCouponJWS(Coupon.Type.PERIODIC, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon5 = CouponIssuer.buildCouponJWS(Coupon.Type.PERIODIC, 1, "test", FEDERATION_ID, btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        AccountingCoupon accountingCoupon1 = new AccountingCoupon(coupon1);
        accountingCoupon1.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        accountingCoupon1.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon1);
        AccountingCoupon accountingCoupon2 = new AccountingCoupon(coupon2);
        accountingCoupon2.setLastConsumptionTimestamp(cleanupTimestamp + 1);
        accountingCoupon2.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon2);
        AccountingCoupon accountingCoupon3 = new AccountingCoupon(coupon3);
        accountingCoupon3.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        accountingCoupon3.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon3);
        AccountingCoupon accountingCoupon4 = new AccountingCoupon(coupon4);
        accountingCoupon4.setLastConsumptionTimestamp(cleanupTimestamp + 1);
        accountingCoupon4.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon4);
        AccountingCoupon accountingCoupon5 = new AccountingCoupon(coupon5);
        accountingCoupon5.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        accountingCoupon5.setStatus(CouponValidationStatus.VALID);
        globalCouponsRegistry.save(accountingCoupon5);

        int cleanedCoupons = issuedCouponsRegistryManagementService.cleanupConsumedCoupons(cleanupTimestamp);
        //checking response
        assertEquals(2, cleanedCoupons);
        //checking db
        assertEquals(3, globalCouponsRegistry.count());
        assertTrue(globalCouponsRegistry.exists(accountingCoupon2.getId()));
        assertTrue(globalCouponsRegistry.exists(accountingCoupon4.getId()));
        assertTrue(globalCouponsRegistry.exists(accountingCoupon5.getId()));
        assertFalse(globalCouponsRegistry.exists(accountingCoupon1.getId()));
        assertFalse(globalCouponsRegistry.exists(accountingCoupon3.getId()));
    }


}
