package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/service.properties")
public class RevocationFunctionalTests extends
        AbstractBTMTestSuite {

    @Autowired
    CouponIssuer couponIssuer;
    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;

    @Test
    public void revokeCouponRESTSuccess() throws
            JWTCreationException,
            BTMException,
            WrongCredentialsException,
            InvalidArgumentsException {

        Coupon coupon = couponIssuer.getDiscreteCoupon();
        assertNotNull(coupon.getCoupon());
        assertTrue(issuedCouponsRepository.exists(coupon.getId()));
        assertEquals(couponValidity, issuedCouponsRepository.findOne(coupon.getId()).getValidity());
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(coupon.getId()).getStatus());

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCouponString(coupon.toString());
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));

        assertTrue(Boolean.parseBoolean(btmClient.revokeCoupon(revocationRequest)));
        assertEquals(IssuedCoupon.Status.REVOKED, issuedCouponsRepository.findOne(coupon.getId()).getStatus());
    }
}