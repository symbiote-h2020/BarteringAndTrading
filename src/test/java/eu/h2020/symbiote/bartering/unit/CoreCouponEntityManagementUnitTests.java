package eu.h2020.symbiote.bartering.unit;

import eu.h2020.symbiote.bartering.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.bartering.TestConfig;
import eu.h2020.symbiote.bartering.communication.CoreBTMClient;
import eu.h2020.symbiote.bartering.config.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
import eu.h2020.symbiote.bartering.services.helpers.CouponIssuer;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import static eu.h2020.symbiote.bartering.TestConfig.NO_CONNECTION_ISSUER_NAME;
import static eu.h2020.symbiote.bartering.TestConfig.SERVICE_ISSUER_NAME;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

@TestPropertySource("/core.properties")
public class CoreCouponEntityManagementUnitTests extends AbstractCoreBTMTestSuite {


    private static final String CERTIFICATE_ALIAS = "btm";
    private static final String KEY_STORE_PASSWORD = "1234567";

    private IComponentSecurityHandler mockedComponentSecurityHandler;
    private ISecurityHandler mockedSecurityHandler;

    @Autowired
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;

    private KeyPair serviceBtmKeyPair;

    @Before
    public void setUp() throws
            Exception {
        super.setUp();
        PrivateKey privateKey = getPrivateKeyTestFromKeystore(TestConfig.SERVICE_KEY_STORE_NAME, KEY_STORE_PASSWORD, CERTIFICATE_ALIAS);
        X509Certificate certificate = getCertificateFromTestKeystore(TestConfig.SERVICE_KEY_STORE_PATH, KEY_STORE_PASSWORD, CERTIFICATE_ALIAS);
        this.serviceBtmKeyPair = new KeyPair(certificate.getPublicKey(), privateKey);

        mockedComponentSecurityHandler = componentSecurityHandlerProvider.getComponentSecurityHandler();
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0dXNlcm5hbWUiLCJzdWIiOiJ0ZXN0Y2xpZW50aWQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.SGNpyl3zRA_ptRhA0lFH0o7-nhf3mpxE95ss37_jHYbCnwlRb4zDvVaYCj9DlpppU4U0y3vIPEqM44vV2UZ5Iw"));
        doReturn(true).when(mockedComponentSecurityHandler).isReceivedServiceResponseVerified(Mockito.any(), Mockito.any(), Mockito.any());
        when(mockedComponentSecurityHandler.generateServiceResponse()).thenReturn("ServiceResponce");
        mockedSecurityHandler = mockedComponentSecurityHandler.getSecurityHandler();
        doReturn(new AAMClient(serverAddress + "/test/caam").getAvailableAAMs().getAvailableAAMs())
                .when(mockedSecurityHandler).getAvailableAAMs();

        doReturn(new HashSet<>(Collections.singletonList("anything"))).when(mockedComponentSecurityHandler).getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any());
    }

    @Test
    public void registerCouponSuccess() throws
            MalformedJWTException,
            ValidationException,
            CertificateException,
            BTMException,
            SecurityHandlerException {
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString)));
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

    @Test(expected = SecurityHandlerException.class)
    public void registerCouponFailCoreAAMNotAvailable() throws
            MalformedJWTException,
            ValidationException,
            CertificateException,
            BTMException,
            SecurityHandlerException {
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                NO_CONNECTION_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString));
    }

    @Test(expected = ValidationException.class)
    public void registerCouponFailMalformedCoupon() throws
            CertificateException,
            BTMException,
            ValidationException,
            MalformedJWTException, SecurityHandlerException {
        //generate coupon using btm cert
        String couponString = "malformedCoupon";
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString));
    }

    @Test(expected = ValidationException.class)
    public void registerCouponFailMismatchOfComponentKeys() throws
            CertificateException,
            BTMException,
            ValidationException,
            MalformedJWTException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            SecurityHandlerException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //generate coupon using random keys
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString));
    }

    @Test(expected = ValidationException.class)
    public void registerCouponFailWrongValValue() throws
            CertificateException,
            BTMException,
            ValidationException,
            MalformedJWTException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            SecurityHandlerException {
        KeyPair keyPair = CryptoHelper.createKeyPair();
        //generate coupon using random keys
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                -5,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString));
    }

    @Test(expected = BTMException.class)
    public void registerCouponFailAlreadyRegistered() throws
            CertificateException,
            BTMException,
            ValidationException,
            MalformedJWTException,
            SecurityHandlerException {
        //generate coupon using random keys
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString)));
        //check if coupon in db
        assertTrue(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        issuedCouponsRegistryManagementService.registerCoupon(new Coupon(couponString));
    }

    @Test
    public void consumeDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWS(Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //consume CouponEntity
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(new Coupon(couponString));
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        accountingCoupon = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(1, accountingCoupon.getUsagesCounter());
        assertNotEquals(0, accountingCoupon.getFirstUseTimestamp());
        assertNotEquals(0, accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
        //consume it again to change its status
        couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(new Coupon(couponString));
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
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //consume CouponEntity
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(new Coupon(couponString));
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        accountingCoupon = globalCouponsRegistry.findOne(accountingCoupon.getId());
        assertEquals(1, accountingCoupon.getUsagesCounter());
        assertNotEquals(0, accountingCoupon.getFirstUseTimestamp());
        assertNotEquals(0, accountingCoupon.getLastConsumptionTimestamp());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
        //consume it again
        couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(new Coupon(couponString));
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
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        accountingCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
        //consume CouponEntity
        CouponValidationStatus couponValidationStatus = issuedCouponsRegistryManagementService.consumeCoupon(new Coupon(couponString));
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

    @Test
    public void validateDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                10,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(10, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
        //usage added
        accountingCoupon.setUsagesCounter(1);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
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
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(10000, couponValidity.getRemainingTime());
        //usage added
        accountingCoupon.setFirstUseTimestamp(new Date().getTime());
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        Thread.sleep(100);
        couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
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
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        //usage added
        accountingCoupon.setFirstUseTimestamp(new Date().getTime());
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        Thread.sleep(100);
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
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
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        accountingCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void validateCouponFailNotRegistered() throws
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                1,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
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
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        //save coupon in db as revoked
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        accountingCoupon.setStatus(CouponValidationStatus.REVOKED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
        //ask for validation
        CouponValidity couponValidity = issuedCouponsRegistryManagementService.isCouponValid(new Coupon(couponString));
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.REVOKED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void cleanupConsumedCouponsSuccess() throws
            MalformedJWTException,
            ValidationException {
        long cleanupTimestamp = 100000;
        //generate some coupons and save them in repo
        String coupon1 = CouponIssuer.buildCouponJWS(Coupon.Type.DISCRETE, 1, SERVICE_ISSUER_NAME, FEDERATION_ID, serviceBtmKeyPair.getPublic(), serviceBtmKeyPair.getPrivate());
        String coupon2 = CouponIssuer.buildCouponJWS(Coupon.Type.DISCRETE, 1, SERVICE_ISSUER_NAME, FEDERATION_ID, serviceBtmKeyPair.getPublic(), serviceBtmKeyPair.getPrivate());
        String coupon3 = CouponIssuer.buildCouponJWS(Coupon.Type.PERIODIC, 1, SERVICE_ISSUER_NAME, FEDERATION_ID, serviceBtmKeyPair.getPublic(), serviceBtmKeyPair.getPrivate());
        String coupon4 = CouponIssuer.buildCouponJWS(Coupon.Type.PERIODIC, 1, SERVICE_ISSUER_NAME, FEDERATION_ID, serviceBtmKeyPair.getPublic(), serviceBtmKeyPair.getPrivate());
        String coupon5 = CouponIssuer.buildCouponJWS(Coupon.Type.PERIODIC, 1, SERVICE_ISSUER_NAME, FEDERATION_ID, serviceBtmKeyPair.getPublic(), serviceBtmKeyPair.getPrivate());
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

    @Test
    public void coreBTMClientRegisterCouponSuccess() throws
            SecurityHandlerException,
            MalformedJWTException {
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //check if coupon not in db
        assertFalse(globalCouponsRegistry.exists(registeredCouponId));
        //register coupon
        assertTrue(coreBTMClient.registerCoupon(couponString));
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

    @Test
    public void coreBTMClientRegisterCouponFailNotPassedAP() throws
            SecurityHandlerException {
        doReturn(new HashSet<>()).when(mockedComponentSecurityHandler).getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any());
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        assertFalse(coreBTMClient.registerCoupon(""));
    }

    @Test
    public void coreBTMClientRegisterCouponFailEmptySecurityRequest() throws
            SecurityHandlerException {
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(""));

        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        assertFalse(coreBTMClient.registerCoupon(""));
    }

    @Test
    public void coreBTMClientConsumeCouponSuccess() throws
            SecurityHandlerException,
            MalformedJWTException,
            ValidationException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        globalCouponsRegistry.save(new AccountingCoupon(couponString));
        //check if coupon in db
        assertTrue(globalCouponsRegistry.exists(registeredCouponId));
        //consume coupon
        assertTrue(coreBTMClient.consumeCoupon(couponString));
        //check the DB
        assertTrue(globalCouponsRegistry.exists(registeredCouponId));
        AccountingCoupon accountingCoupon = globalCouponsRegistry.findOne(registeredCouponId);
        assertEquals(couponString, accountingCoupon.getCouponString());
        assertEquals(1, accountingCoupon.getUsagesCounter());
        assertEquals(Coupon.Type.DISCRETE, accountingCoupon.getType());
        assertEquals(CouponValidationStatus.VALID, accountingCoupon.getStatus());
    }

    @Test(expected = WrongCredentialsException.class)
    public void coreBTMClientConsumeCouponFailNotPassedAP() throws
            SecurityHandlerException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        doReturn(new HashSet<>()).when(mockedComponentSecurityHandler).getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any());
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        assertFalse(coreBTMClient.consumeCoupon(""));
    }

    @Test(expected = InvalidArgumentsException.class)
    public void coreBTMClientConsumeCouponFailEmptySecurityRequest() throws
            SecurityHandlerException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(""));
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        assertFalse(coreBTMClient.consumeCoupon(""));
    }

    @Test
    public void coreBTMClientIsCouponValidSuccess() throws
            SecurityHandlerException,
            MalformedJWTException,
            ValidationException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        //generate coupon using btm cert
        String couponString = CouponIssuer.buildCouponJWS(
                Coupon.Type.DISCRETE,
                2,
                SERVICE_ISSUER_NAME,
                FEDERATION_ID,
                serviceBtmKeyPair.getPublic(),
                serviceBtmKeyPair.getPrivate());
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        globalCouponsRegistry.save(new AccountingCoupon(couponString));
        //check if coupon in db
        assertTrue(globalCouponsRegistry.exists(registeredCouponId));
        //check coupon
        CouponValidity couponValidity = coreBTMClient.isCouponValid(couponString);
        //check the validity
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
    }

    @Test(expected = WrongCredentialsException.class)
    public void coreBTMClientIsCouponValidFailNotPassedAP() throws
            SecurityHandlerException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        doReturn(new HashSet<>()).when(mockedComponentSecurityHandler).getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any());
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        coreBTMClient.isCouponValid("");
    }

    @Test(expected = InvalidArgumentsException.class)
    public void coreBTMClientIsCouponValidFailEmptySecurityRequest() throws
            SecurityHandlerException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenReturn(new SecurityRequest(""));
        CoreBTMClient coreBTMClient = new CoreBTMClient(serverAddress, mockedComponentSecurityHandler);
        coreBTMClient.isCouponValid("");
    }

}
