package eu.h2020.symbiote.security.functional;


import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/service.properties")
public class ValidationFunctionalTests extends
        AbstractBTMTestSuite {

    @Autowired
    CouponIssuer couponIssuer;

    @Test
    public void validateCouponRESTSuccess() throws
            JWTCreationException,
            BTMException {

        Coupon coupon = couponIssuer.getDiscreteCoupon();
        assertTrue(storedCouponsRepository.exists(coupon.getId()));
        assertNotNull(coupon.getCoupon());

        CouponValidationStatus status = btmClient.validateCoupon(coupon.getCoupon());
        assertEquals(CouponValidationStatus.VALID, status);
    }

}
