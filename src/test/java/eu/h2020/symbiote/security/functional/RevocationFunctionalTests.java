package eu.h2020.symbiote.security.functional;

import eu.h2020.symbiote.security.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import static eu.h2020.symbiote.security.services.helpers.CouponIssuer.buildCouponJWT;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@TestPropertySource("/core.properties")
public class RevocationFunctionalTests extends
        AbstractCoreBTMTestSuite {

    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;

    @Test
    public void revokeCouponRESTSuccess() throws
            BTMException,
            WrongCredentialsException,
            InvalidArgumentsException,
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException {

        Map<String, String> attributes = new HashMap<>();
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String couponString = buildCouponJWT(
                attributes,
                Coupon.Type.DISCRETE,
                100,
                "coupon",
                keyPair.getPublic(),
                keyPair.getPrivate()
        );
        assertNotNull(couponString);
        RegisteredCoupon registeredCoupon = new RegisteredCoupon(couponString);
        registeredCouponRepository.save(registeredCoupon);
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCouponString(couponString);
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));

        assertTrue(Boolean.parseBoolean(btmClient.revokeCoupon(revocationRequest)));
        assertEquals(CouponValidationStatus.REVOKED_COUPON, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());
    }
}
