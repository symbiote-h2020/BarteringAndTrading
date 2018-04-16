package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.security.services.RevocationService;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertEquals;

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


    @Test
    public void revokeCouponByAdminSuccess() throws
            JWTCreationException {

        // acquiring valid coupon
        Coupon discreteCoupon = couponIssuer.getDiscreteCoupon();

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCouponString(discreteCoupon.toString());

        // verify the user token is not yet revoked
        assertEquals(IssuedCoupon.Status.VALID, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());
        // revocation
        revocationService.revoke(revocationRequest);

        // verify the user token is revoked
        assertEquals(IssuedCoupon.Status.REVOKED, issuedCouponsRepository.findOne(discreteCoupon.getId()).getStatus());
    }
}