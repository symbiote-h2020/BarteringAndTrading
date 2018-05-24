package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import eu.h2020.symbiote.security.services.RevocationService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static eu.h2020.symbiote.security.services.helpers.CouponIssuer.buildCouponJWT;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

/**
 * Test suite for revocation (unit tests)
 *
 * @author Jakub Toczek (PSNC)
 */
@TestPropertySource("/core.properties")
public class RevocationUnitTests extends
        AbstractCoreBTMTestSuite {

    @Autowired
    private RevocationService revocationService;
    @Autowired
    private CertificationAuthorityHelper certificationAuthorityHelper;


    @Test
    public void revokeCouponByAdminSuccess() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException {

        // acquiring valid coupon
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String couponString = buildCouponJWT(
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

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString(couponString);

        // verify the user coupon is not yet revoked
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());
        // revocation
        RevocationResponse response = revocationService.revoke(revocationRequest);

        // verify the user coupon is revoked
        assertTrue(response.isRevoked());
        assertEquals(CouponValidationStatus.REVOKED_COUPON, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());
    }

    @Test
    public void revokeCouponFailWrongRevocationRequest() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            MalformedJWTException,
            ValidationException {
        // acquiring valid coupon
        KeyPair keyPair = CryptoHelper.createKeyPair();
        String couponString = buildCouponJWT(
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
        // verify the user token is not yet revoked
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials("wrongUsername", BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString(registeredCoupon.getCouponString());
        // revocation using wrong admin name
        RevocationResponse response = revocationService.revoke(revocationRequest);

        // verify the user coupon is not revoked
        assertFalse(response.isRevoked());
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());

        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, "wrong password"));
        // revocation using wrong admin password
        response = revocationService.revoke(revocationRequest);

        // verify the user coupon is not revoked
        assertFalse(response.isRevoked());
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());

        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        // revocation using wrong revocation type
        response = revocationService.revoke(revocationRequest);

        // verify the user coupon is not revoked
        assertFalse(response.isRevoked());
        assertEquals(CouponValidationStatus.VALID, registeredCouponRepository.findOne(registeredCoupon.getId()).getStatus());

    }

    @Test
    public void revokeCouponFailWrongCoupon() {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString("wrongCoupon");
        // revocation using wrong coupon
        RevocationResponse response = revocationService.revoke(revocationRequest);
        assertFalse(response.isRevoked());
    }

    @Test
    public void revokeCouponFailWrongIssuer() throws ValidationException {
        Coupon coupon = new Coupon(CouponIssuer.buildCouponJWT(
                Coupon.Type.DISCRETE,
                1,
                "Wrong Issuer",
                FEDERATION_ID,
                certificationAuthorityHelper.getBTMPublicKey(),
                certificationAuthorityHelper.getBTMPrivateKey()
        ));
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString(coupon.getCoupon());
        // revocation using wrong coupon
        RevocationResponse response = revocationService.revoke(revocationRequest);
        assertFalse(response.isRevoked());
    }
}