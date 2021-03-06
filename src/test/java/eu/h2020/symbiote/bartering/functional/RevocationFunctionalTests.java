package eu.h2020.symbiote.bartering.functional;

import eu.h2020.symbiote.bartering.AbstractCoreBTMTestSuite;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.context.TestPropertySource;

import java.security.KeyPair;

import static eu.h2020.symbiote.bartering.services.helpers.CouponIssuer.buildCouponJWS;
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
        couponString = buildCouponJWS(
                Coupon.Type.DISCRETE,
                100,
                "coupon",
                FEDERATION_ID,
                keyPair.getPublic(),
                keyPair.getPrivate()
        );
        assertNotNull(couponString);
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        globalCouponsRegistry.save(accountingCoupon);
        assertEquals(CouponValidationStatus.VALID, globalCouponsRegistry.findOne(accountingCoupon.getId()).getStatus());
    }

    @Test
    public void revokeCouponRESTSuccess() throws
            MalformedJWTException,
            ValidationException,
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCouponString(couponString);
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setCredentials(new Credentials(BTMOwnerUsername, BTMOwnerPassword));

        assertTrue(Boolean.parseBoolean(btmClient.revokeCoupon(revocationRequest)));
        //checking db
        AccountingCoupon accountingCoupon = new AccountingCoupon(couponString);
        assertEquals(CouponValidationStatus.REVOKED_COUPON, globalCouponsRegistry.findOne(accountingCoupon.getId()).getStatus());
    }
}
