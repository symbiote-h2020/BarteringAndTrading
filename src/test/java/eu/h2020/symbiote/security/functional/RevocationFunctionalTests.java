package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/core.properties")
public class RevocationFunctionalTests extends
        AbstractBTMTestSuite {

    @Autowired
    CouponIssuer couponIssuer;
    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;

    @Ignore
    @Test
    public void revokeCouponRESTSuccess() throws JWTCreationException, AAMException {

        Coupon coupon = couponIssuer.getDiscreteCoupon();
        assertTrue(validCouponsRepository.exists(coupon.getId()));
        assertEquals(couponValidity, validCouponsRepository.findOne(coupon.getId()).getValidity());
        assertNotNull(coupon.getCoupon());

        CouponValidationStatus status = btmClient.validateCoupon(coupon.getCoupon());
        assertEquals(CouponValidationStatus.VALID, status);
    }
}
