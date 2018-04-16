package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.security.services.RevocationService;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.util.HashMap;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * Test suite for revocation (unit tests)
 *
 * @author Jakub Toczek (PSNC)
 */
@TestPropertySource("/core.properties")
public class RevocationUnitTests extends
        AbstractBTMTestSuite {

    @Autowired
    private RevocationService revocationService;
    @Autowired
    private CouponIssuer couponIssuer;
    @Autowired
    private CertificationAuthorityHelper certificationAuthorityHelper;


    @Test
    public void revokeCouponByAdminSuccess() throws
            JWTCreationException {

        // acquiring valid coupon
        Coupon discreteCoupon = couponIssuer.getDiscreteCoupon();

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString(discreteCoupon.getCoupon());

        // verify the user coupon is not yet revoked
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());
        // revocation
        RevocationResponse response = revocationService.revoke(revocationRequest);

        // verify the user coupon is revoked
        assertTrue(response.isRevoked());
        assertEquals(IssuedCoupon.Status.REVOKED, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());
    }

    @Test
    public void revokeCouponFailWrongRevocationRequest() throws
            JWTCreationException {
        // acquiring valid coupon
        Coupon discreteCoupon = couponIssuer.getDiscreteCoupon();
        // verify the user token is not yet revoked
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials("wrongUsername", BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString(discreteCoupon.getCoupon());
        // revocation using wrong admin name
        RevocationResponse response = revocationService.revoke(revocationRequest);

        // verify the user coupon is not revoked
        assertFalse(response.isRevoked());
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());

        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, "wrong password"));
        // revocation using wrong admin password
        response = revocationService.revoke(revocationRequest);

        // verify the user coupon is not revoked
        assertFalse(response.isRevoked());
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());

        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
        // revocation using wrong revocation type
        response = revocationService.revoke(revocationRequest);

        // verify the user coupon is not revoked
        assertFalse(response.isRevoked());
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());

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
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                1,
                "Wrong Issuer",
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