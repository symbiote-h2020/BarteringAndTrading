package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.security.KeyPair;

import static eu.h2020.symbiote.security.services.helpers.CouponIssuer.buildCouponJWT;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/core.properties")
public class RevocationFunctionalTests extends
        AbstractCoreBTMTestSuite {

    private String couponString;

    @Override
    @Before
    public void setUp() throws
            Exception {
        super.setUp();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        couponString = buildCouponJWT(
                Coupon.Type.DISCRETE,
                100,
                "coupon",
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate()
        );
        assertNotNull(couponString);
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());
    }

    @Test
    public void revokeCouponRESTSuccess() throws
            BTMException,
            WrongCredentialsException,
            InvalidArgumentsException,
            MalformedJWTException,
            ValidationException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCouponString(couponString);
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));

        assertTrue(Boolean.parseBoolean(btmClient.revokeCoupon(revocationRequest)));
        //checking db
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        assertEquals(CouponValidationStatus.REVOKED_COUPON, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());
    }
}
