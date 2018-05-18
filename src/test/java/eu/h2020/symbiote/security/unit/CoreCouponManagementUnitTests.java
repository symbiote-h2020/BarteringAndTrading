package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RegisteredCouponRepository;
import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import eu.h2020.symbiote.security.services.CoreCouponManagementService;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
@TestPropertySource("/core.properties")
public class CoreCouponManagementUnitTests {
    @Autowired
    RegisteredCouponRepository registeredCouponRepository;
    @Autowired
    CoreCouponManagementService coreCouponManagementService;
    private KeyPair btmKeyPair;

    @Before
    public void setUp() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException {
        this.btmKeyPair = CryptoHelper.createKeyPair();
    }

    @Test
    public void consumeDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 2, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        //consume Coupon
        CouponValidationStatus couponValidationStatus = coreCouponManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        registeredCoupon = registeredCouponRepository.findOne(registeredCoupon.getId());
        assertEquals(1, registeredCoupon.getUsages());
        assertNotEquals(0, registeredCoupon.getFirstUseTimestamp());
        assertNotEquals(0, registeredCoupon.getLastConsumptionTimestamp());
        assertEquals(StoredCoupon.Status.VALID, registeredCoupon.getStatus());
        //consume it again to change its status
        couponValidationStatus = coreCouponManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        registeredCoupon = registeredCouponRepository.findOne(registeredCoupon.getId());
        assertEquals(2, registeredCoupon.getUsages());
        assertNotEquals(registeredCoupon.getFirstUseTimestamp(), registeredCoupon.getLastConsumptionTimestamp());
        assertEquals(StoredCoupon.Status.CONSUMED, registeredCoupon.getStatus());
    }

    @Test
    public void consumePeriodicCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 10000, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        //consume Coupon
        CouponValidationStatus couponValidationStatus = coreCouponManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        registeredCoupon = registeredCouponRepository.findOne(registeredCoupon.getId());
        assertEquals(1, registeredCoupon.getUsages());
        assertNotEquals(0, registeredCoupon.getFirstUseTimestamp());
        assertNotEquals(0, registeredCoupon.getLastConsumptionTimestamp());
        assertEquals(StoredCoupon.Status.VALID, registeredCoupon.getStatus());
        //consume it again
        couponValidationStatus = coreCouponManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.VALID, couponValidationStatus);
        //check registered coupon in db
        registeredCoupon = registeredCouponRepository.findOne(registeredCoupon.getId());
        assertEquals(2, registeredCoupon.getUsages());
        assertNotEquals(registeredCoupon.getFirstUseTimestamp(), registeredCoupon.getLastConsumptionTimestamp());
        assertEquals(StoredCoupon.Status.VALID, registeredCoupon.getStatus());
    }

    @Test
    public void consumeCouponFailCouponNotValid() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 10000, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCoupon.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon);
        //consume Coupon
        CouponValidationStatus couponValidationStatus = coreCouponManagementService.consumeCoupon(couponString);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidationStatus);
        //check if coupon did not changed in db
        RegisteredCoupon registeredCouponDB = registeredCouponRepository.findOne(registeredCoupon.getId());
        assertEquals(registeredCoupon.getUsages(), registeredCouponDB.getUsages());
        assertEquals(registeredCoupon.getFirstUseTimestamp(), registeredCouponDB.getFirstUseTimestamp());
        assertEquals(registeredCoupon.getLastConsumptionTimestamp(), registeredCouponDB.getLastConsumptionTimestamp());
        assertEquals(registeredCoupon.getStatus(), registeredCouponDB.getStatus());
        assertEquals(registeredCoupon.getType(), registeredCouponDB.getType());
        assertEquals(registeredCoupon.getValidity(), registeredCouponDB.getValidity());
        assertEquals(registeredCoupon.getCouponString(), registeredCouponDB.getCouponString());
        assertEquals(registeredCoupon.getIssuer(), registeredCouponDB.getIssuer());
    }

    @Test(expected = MalformedJWTException.class)
    public void consumeCouponFailMalformedCoupon() throws
            MalformedJWTException {
        String couponString = "MalformedCoupon";
        coreCouponManagementService.consumeCoupon(couponString);
    }

    @Test
    public void validateDiscreteCouponSuccess() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 10, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(10, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
        //usage added
        registeredCoupon.setUsages(1);
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        couponValidity = coreCouponManagementService.isCouponValid(couponString);
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
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 10000, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.VALID, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(10000, couponValidity.getRemainingTime());
        //usage added
        registeredCoupon.setFirstUseTimestamp(new Date().getTime());
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        Thread.sleep(1);
        couponValidity = coreCouponManagementService.isCouponValid(couponString);
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
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        //usage added
        registeredCoupon.setFirstUseTimestamp(new Date().getTime());
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        Thread.sleep(1);
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
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
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCoupon.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test
    public void validateCouponFailNotRegistered() throws
            MalformedJWTException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //ask for validation
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
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
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //save coupon in db as revoked
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCoupon.setStatus(StoredCoupon.Status.REVOKED);
        registeredCouponRepository.save(registeredCoupon);
        //ask for validation
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
        assertNotNull(couponValidity);
        assertEquals(CouponValidationStatus.REVOKED_COUPON, couponValidity.getStatus());
        assertEquals(0, couponValidity.getRemainingUsages());
        assertEquals(0, couponValidity.getRemainingTime());
    }

    @Test(expected = MalformedJWTException.class)
    public void validateCouponFailMalformedCoupon() throws
            MalformedJWTException {
        String couponString = "MalformedCoupon";
        coreCouponManagementService.isCouponValid(couponString);
    }

    @Test
    public void validateCouponFailCouponMismatch() throws
            MalformedJWTException,
            ValidationException {
        //generate coupon
        String couponString = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        //put it in repo with changed couponString
        RegisteredCoupon registeredCoupon1 = new RegisteredCoupon(couponString);
        ReflectionTestUtils.setField(registeredCoupon1, "couponString", "WrongCouponString");
        registeredCouponRepository.save(registeredCoupon1);
        //ask for validation
        CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
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
        String coupon1 = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon2 = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.DISCRETE, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon3 = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon4 = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        String coupon5 = CouponIssuer.buildCouponJWT(new HashMap<>(), Coupon.Type.PERIODIC, 1, "test", btmKeyPair.getPublic(), btmKeyPair.getPrivate());
        RegisteredCoupon registeredCoupon1 = new RegisteredCoupon(coupon1);
        registeredCoupon1.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        registeredCoupon1.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon1);
        RegisteredCoupon registeredCoupon2 = new RegisteredCoupon(coupon2);
        registeredCoupon2.setLastConsumptionTimestamp(cleanupTimestamp + 1);
        registeredCoupon2.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon2);
        RegisteredCoupon registeredCoupon3 = new RegisteredCoupon(coupon3);
        registeredCoupon3.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        registeredCoupon3.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon3);
        RegisteredCoupon registeredCoupon4 = new RegisteredCoupon(coupon4);
        registeredCoupon4.setLastConsumptionTimestamp(cleanupTimestamp + 1);
        registeredCoupon4.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon4);
        RegisteredCoupon registeredCoupon5 = new RegisteredCoupon(coupon5);
        registeredCoupon5.setLastConsumptionTimestamp(cleanupTimestamp - 1);
        registeredCoupon5.setStatus(StoredCoupon.Status.VALID);
        registeredCouponRepository.save(registeredCoupon5);

        int cleanedCoupons = coreCouponManagementService.cleanupConsumedCoupons(cleanupTimestamp);
        //checking response
        assertEquals(2, cleanedCoupons);
        //checking db
        assertEquals(3, registeredCouponRepository.count());
        assertTrue(registeredCouponRepository.exists(registeredCoupon2.getId()));
        assertTrue(registeredCouponRepository.exists(registeredCoupon4.getId()));
        assertTrue(registeredCouponRepository.exists(registeredCoupon5.getId()));
        assertFalse(registeredCouponRepository.exists(registeredCoupon1.getId()));
        assertFalse(registeredCouponRepository.exists(registeredCoupon3.getId()));
    }


}