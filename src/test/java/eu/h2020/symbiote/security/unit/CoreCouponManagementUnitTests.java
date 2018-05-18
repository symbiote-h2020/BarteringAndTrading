package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

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
        registeredCoupon1.setConsumptionTimestamp(cleanupTimestamp - 1);
        registeredCoupon1.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon1);
        RegisteredCoupon registeredCoupon2 = new RegisteredCoupon(coupon2);
        registeredCoupon2.setConsumptionTimestamp(cleanupTimestamp + 1);
        registeredCoupon2.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon2);
        RegisteredCoupon registeredCoupon3 = new RegisteredCoupon(coupon3);
        registeredCoupon3.setConsumptionTimestamp(cleanupTimestamp - 1);
        registeredCoupon3.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon3);
        RegisteredCoupon registeredCoupon4 = new RegisteredCoupon(coupon4);
        registeredCoupon4.setConsumptionTimestamp(cleanupTimestamp + 1);
        registeredCoupon4.setStatus(StoredCoupon.Status.CONSUMED);
        registeredCouponRepository.save(registeredCoupon4);
        RegisteredCoupon registeredCoupon5 = new RegisteredCoupon(coupon5);
        registeredCoupon5.setConsumptionTimestamp(cleanupTimestamp - 1);
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
