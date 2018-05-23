package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBTMTestSuite;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@TestPropertySource("/service.properties")
public class BarteralAccessUnitTests extends AbstractBTMTestSuite {

    @Autowired
    ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String BTM_AP_NAME = "btmAPName";
    private String PLATFORM_ID = "testPlatformId";

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        Set<String> set = new HashSet<>();
        set.add(BTM_AP_NAME);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(set);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        ReflectionTestUtils.setField(barteralAccessManagementService, "btmCoreAddress", serverAddress + "/test/btm");
        ReflectionTestUtils.setField(barteralAccessManagementService, "coreInterfaceAddress", serverAddress + "/test/caam");
        dummyCoreAAMAndBTM.registrationStatus = HttpStatus.OK;
        dummyCoreAAMAndBTM.couponValidationStatus = CouponValidationStatus.VALID;
        dummyPlatformBTM.receivedCouponIssuer = dummyPlatformId;
    }

    @Test
    public void authorizeBarteralAccessSuccessReceivedLocalCoupon() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException {
        dummyPlatformBTM.receivedCouponIssuer = certificationAuthorityHelper.getBTMPlatformInstanceIdentifier();
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "resourceId", Coupon.Type.DISCRETE);
        assertTrue(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
        //no coupon saved in db
        assertEquals(0, storedCouponsRepository.count());
    }

    @Test
    public void authorizeBarteralAccessSuccessReceivedForeignCoupon() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException {
        dummyPlatformBTM.receivedCouponIssuer = dummyPlatformId;
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "resourceId", Coupon.Type.DISCRETE);
        assertTrue(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
        //coupon saved in db
        assertEquals(1, storedCouponsRepository.count());
    }

    @Test(expected = AAMException.class)
    public void authorizeBarteralAccessFailNoCoreConnection() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException {
        ReflectionTestUtils.setField(barteralAccessManagementService, "coreInterfaceAddress", serverAddress + "/wrong_address");
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test(expected = BTMException.class)
    public void authorizeBarteralAccessFailClientPlatformNotRegistered() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException {
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest("notRegisteredPlatformId", "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);

    }

    @Test(expected = SecurityHandlerException.class)
    public void authorizeBarteralAccessFailSecurityRequestCreation() throws
            SecurityHandlerException,
            ValidationException,
            BTMException,
            AAMException {
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenThrow(new SecurityHandlerException(""));
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test
    public void authorizeBarteralAccessFailReceivedLocalCouponNotValid() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException {
        dummyPlatformBTM.receivedCouponIssuer = certificationAuthorityHelper.getBTMPlatformInstanceIdentifier();
        dummyCoreAAMAndBTM.consumptionStatus = HttpStatus.BAD_REQUEST;
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "resourceId", Coupon.Type.DISCRETE);
        assertFalse(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
    }

    @Test
    public void authorizeBarteralAccessFailReceivedForeignCouponNotValid() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException {
        dummyCoreAAMAndBTM.couponValidationStatus = CouponValidationStatus.CONSUMED_COUPON;
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "resourceId", Coupon.Type.DISCRETE);
        assertFalse(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
    }

    @Test
    public void getCouponSuccessReturnedStoredCoupon() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        //put proper VALID coupon into repo
        StoredCoupon storedCoupon = new StoredCoupon(couponIssuer.getCoupon(Coupon.Type.DISCRETE));
        storedCouponsRepository.save(storedCoupon);
        assertEquals(CouponValidationStatus.VALID, storedCoupon.getStatus());
        //create request (checking SecurityRequest is mocked) using own platformId
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, certificationAuthorityHelper.getBTMPlatformInstanceIdentifier(), null);
        String couponString = barteralAccessManagementService.getCoupon(couponRequest);
        //returned coupon should not be empty
        assertNotNull(couponString);
        Coupon coupon = new Coupon(couponString);
        //returned coupon should have proper type
        assertEquals(Coupon.Type.DISCRETE, coupon.getType());
        //returned coupon should be different than those stored
        assertEquals(storedCoupon.getId(), coupon.getId());
    }

    @Test
    public void getCouponSuccessNoStoredCouponsAndReturnedNewCoupon() throws
            ValidationException,
            BTMException,
            JWTCreationException {
        //check if repo is empty
        assertEquals(0, storedCouponsRepository.count());
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, PLATFORM_ID, null);
        String couponString = barteralAccessManagementService.getCoupon(couponRequest);
        //returned coupon should not be empty
        assertNotNull(couponString);
        Coupon coupon = new Coupon(couponString);
        //returned coupon should have proper type
        assertEquals(Coupon.Type.DISCRETE, coupon.getType());
    }

    @Test
    public void getCouponSuccessStoredCouponsUpdatedAndReturnedNewCoupon() throws
            ValidationException,
            BTMException,
            JWTCreationException {
        // change dummy Core BTM to return proper validation status
        dummyCoreAAMAndBTM.couponValidationStatus = CouponValidationStatus.CONSUMED_COUPON;
        //put proper VALID coupon into repo
        StoredCoupon storedCoupon = new StoredCoupon(couponIssuer.getCoupon(Coupon.Type.DISCRETE));
        storedCouponsRepository.save(storedCoupon);
        assertEquals(CouponValidationStatus.VALID, storedCoupon.getStatus());
        //create request (checking SecurityRequest is mocked) using own platformId
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, certificationAuthorityHelper.getBTMPlatformInstanceIdentifier(), null);
        String couponString = barteralAccessManagementService.getCoupon(couponRequest);
        //returned coupon should not be empty
        assertNotNull(couponString);
        Coupon coupon = new Coupon(couponString);
        //returned coupon should have proper type
        assertEquals(Coupon.Type.DISCRETE, coupon.getType());
        //returned coupon should be different than those stored
        assertNotEquals(storedCoupon.getId(), coupon.getId());
        //stored coupon status should be changed
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, storedCouponsRepository.findOne(storedCoupon.getId()).getStatus());
    }

    @Test(expected = ValidationException.class)
    public void getCouponFailInvalidSecurityRequest() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        // set mock to return that SecurityRequest do not pass AP
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.anyMap(), Mockito.any())).thenReturn(new HashSet<>());
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, PLATFORM_ID, null);
        barteralAccessManagementService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getCouponFailNoCoreBTMConnection() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        ReflectionTestUtils.setField(barteralAccessManagementService, "btmCoreAddress", "Wrong value");
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, PLATFORM_ID, null);
        barteralAccessManagementService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getCouponFailNewCouponRegistrationError() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        // change dummy Core BTM to return proper registrationStatus
        dummyCoreAAMAndBTM.registrationStatus = HttpStatus.BAD_REQUEST;
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, PLATFORM_ID, null);
        barteralAccessManagementService.getCoupon(couponRequest);
    }


}
