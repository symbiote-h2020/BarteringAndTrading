package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.ManageCouponService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

@TestPropertySource("/core.properties")
public class CouponIssuingUnitTests extends
        AbstractBTMTestSuite {

    @Autowired
    ManageCouponService manageCouponService;
    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;

    @Before
    public void before() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress + "/test/caam");
    }

    @After
    public void after() {
        ReflectionTestUtils.setField(manageCouponService, "coreInterfaceAddress", serverAddress);
    }

    @Test
    public void getDiscreteCouponSuccess() throws CertificateException, JWTCreationException, ValidationException, MalformedJWTException, InvalidArgumentsException, IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, UnrecoverableKeyException {

        String componentId = "testComponentId";
        HomeCredentials homeCredentials = new HomeCredentials(null,
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentId,
                null,
                getPrivateKeyTestFromKeystore("keystores/core.p12",
                        KEY_STORE_PASSWORD,
                        PV_KEY_PASSWORD,
                        "registry-core-1"));
        String loginRequest = CryptoHelper.buildJWTAcquisitionRequest(homeCredentials);

        Coupon discreteCoupon = manageCouponService.getDiscreteCoupon(loginRequest);

        assertEquals(Coupon.Type.DISCRETE, discreteCoupon.getType());
        assertEquals(couponValidity.toString(), discreteCoupon.getClaims().get("val").toString());
        assertTrue(issuedCouponsRepository.exists(discreteCoupon.getId()));
        assertEquals(couponValidity, issuedCouponsRepository.findOne(discreteCoupon.getId()).getValidity());
    }


}
