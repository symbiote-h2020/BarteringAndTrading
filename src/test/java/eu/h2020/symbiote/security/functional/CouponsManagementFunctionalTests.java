package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.services.ManageCouponService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

@TestPropertySource("/service.properties")
public class CouponsManagementFunctionalTests extends
        AbstractBTMTestSuite {

    @Autowired
    CouponIssuer couponIssuer;
    @Autowired
    CertificationAuthorityHelper certificationAuthorityHelper;
    @MockBean
    ManageCouponService manageCouponService;
    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;

    @Before
    public void before() throws
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException,
            JWTCreationException {
        Coupon coupon = couponIssuer.getDiscreteCoupon();
        when(manageCouponService.getCoupon(Mockito.anyString())).thenReturn(coupon);
    }

    @Test
    public void getDiscreteCouponRESTSuccess() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            BTMException {

        String couponRequest = "Valid Coupon Request";
        String discreteCoupon = btmClient.getDiscreteCoupon(couponRequest);
        assertNotNull(discreteCoupon);
        JWTClaims claimsFromToken = JWTEngine.getClaimsFromJWT(discreteCoupon);
        assertEquals(Coupon.Type.DISCRETE, Coupon.Type.valueOf(claimsFromToken.getTtyp()));
        assertEquals(couponValidity.toString(), claimsFromToken.getVal());
    }

    @Test(expected = MalformedJWTException.class)
    public void getDiscreteCouponRESTFailMalformedCouponRequest() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {

        when(manageCouponService.getCoupon(Mockito.anyString())).thenThrow(new MalformedJWTException());
        btmClient.getDiscreteCoupon("login request");
    }

    @Test(expected = BTMException.class)
    public void getDiscreteCouponRESTFailNoCoreCommunication() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {

        when(manageCouponService.getCoupon(Mockito.anyString())).thenThrow(new BTMException());
        btmClient.getDiscreteCoupon("Valid Coupon Request");
    }

    @Test(expected = MalformedJWTException.class)
    public void getDiscreteCouponRESTFailNoIssuerOrSubject() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {

        when(manageCouponService.getCoupon(Mockito.anyString())).thenThrow(new InvalidArgumentsException());
        btmClient.getDiscreteCoupon("Coupon Request without ISS or SUB");
    }

    @Test(expected = BTMException.class)
    public void getDiscreteCouponRESTFailErrorDuringCreation() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {

        when(manageCouponService.getCoupon(Mockito.anyString())).thenThrow(new JWTCreationException());
        btmClient.getDiscreteCoupon("Valid Coupon Request");
    }

    @Test(expected = WrongCredentialsException.class)
    public void getDiscreteCouponRESTFailNotValidRequest() throws
            MalformedJWTException,
            JWTCreationException,
            WrongCredentialsException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {

        when(manageCouponService.getCoupon(Mockito.anyString())).thenThrow(new ValidationException("Not important"));
        btmClient.getDiscreteCoupon("Invalid Coupon Request");
    }

}
