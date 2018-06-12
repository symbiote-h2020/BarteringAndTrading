package eu.h2020.symbiote.bartering.unit;

import eu.h2020.symbiote.bartering.AbstractBTMTestSuite;
import eu.h2020.symbiote.bartering.repositories.entities.StoredCoupon;
import eu.h2020.symbiote.bartering.services.helpers.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@TestPropertySource("/service.properties")
public class BarteralAccessUnitTests extends AbstractBTMTestSuite {

    @Autowired
    ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String BTM_AP_NAME = "btmAPName";
    private String PLATFORM_ID = "testPlatformId";
    private String federationId = "testFederationId";
    private Federation federation;

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
        // federation adding
        federation = new Federation();
        federation.setId(federationId);
        List<FederationMember> federationMembers = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId(dummyPlatformId);
        federationMembers.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId(couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier());
        federationMembers.add(federationMember);
        federation.setMembers(federationMembers);

    }

    @Test
    public void authorizeBarteralAccessSuccessReceivedLocalCoupon() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyPlatformBTM.receivedCouponIssuer = couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier();
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        assertTrue(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
        //no coupon saved in db
        assertEquals(0, storedCouponsRepository.count());
    }

    @Test
    public void authorizeBarteralAccessSuccessReceivedForeignCoupon() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyPlatformBTM.receivedCouponIssuer = dummyPlatformId;
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        assertTrue(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
        //coupon saved in db
        assertEquals(1, storedCouponsRepository.count());
    }

    @Test(expected = InvalidArgumentsException.class)
    public void authorizeBarteralAccessFailNoFederation() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test(expected = ValidationException.class)
    public void authorizeBarteralAccessFailNoLocalPlatformInFederation() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        //remove local platform from federation
        federation.getMembers().remove(1);
        federationsRepository.save(federation);
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test(expected = ValidationException.class)
    public void authorizeBarteralAccessFailNoForeignPlatformInFederation() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        //remove foreign platform from federation
        federation.getMembers().remove(0);
        federationsRepository.save(federation);
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test(expected = AAMException.class)
    public void authorizeBarteralAccessFailNoCoreConnection() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {

        federationsRepository.save(federation);
        ReflectionTestUtils.setField(barteralAccessManagementService, "coreInterfaceAddress", serverAddress + "/wrong_address");
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test(expected = BTMException.class)
    public void authorizeBarteralAccessFailClientsPlatformNotRegistered() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        //putting not registered platform into federation
        List<FederationMember> federationMembers = new ArrayList<>();
        FederationMember federationMember = new FederationMember();
        federationMember.setPlatformId("notRegisteredPlatformId");
        federationMembers.add(federationMember);
        federationMember = new FederationMember();
        federationMember.setPlatformId(couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier());
        federationMembers.add(federationMember);
        federation.setMembers(federationMembers);
        federationsRepository.save(federation);

        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest("notRegisteredPlatformId", federationId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test
    public void authorizeBarteralAccessFailReturnedCouponWithWrongFederationId() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        federation.setId("wrongId");
        federationsRepository.save(federation);
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, "wrongId", "resourceId", Coupon.Type.DISCRETE);
        assertFalse(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
    }

    @Test(expected = SecurityHandlerException.class)
    public void authorizeBarteralAccessFailSecurityRequestCreation() throws
            SecurityHandlerException,
            ValidationException,
            BTMException,
            AAMException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenThrow(new SecurityHandlerException(""));
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest);
    }

    @Test
    public void authorizeBarteralAccessFailReceivedLocalCouponNotValid() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyPlatformBTM.receivedCouponIssuer = couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier();
        dummyCoreAAMAndBTM.consumptionStatus = HttpStatus.BAD_REQUEST;
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        assertFalse(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
    }

    @Test
    public void authorizeBarteralAccessFailReceivedForeignCouponNotValid() throws
            SecurityHandlerException,
            BTMException,
            AAMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyCoreAAMAndBTM.couponValidationStatus = CouponValidationStatus.CONSUMED_COUPON;
        BarteralAccessRequest barteralAccessRequest = new BarteralAccessRequest(dummyPlatformId, federationId, "resourceId", Coupon.Type.DISCRETE);
        assertFalse(barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest));
    }

    @Test
    public void getCouponSuccessReturnedStoredCoupon() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        //put proper VALID coupon into repo
        StoredCoupon storedCoupon = new StoredCoupon(couponIssuer.getCoupon(Coupon.Type.DISCRETE, federationId));
        storedCouponsRepository.save(storedCoupon);
        assertEquals(CouponValidationStatus.VALID, storedCoupon.getStatus());
        //create request (checking SecurityRequest is mocked) using own platformId
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, federationId, couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier(), null);
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
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, federationId, PLATFORM_ID, null);
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
        StoredCoupon storedCoupon = new StoredCoupon(couponIssuer.getCoupon(Coupon.Type.DISCRETE, federationId));
        storedCouponsRepository.save(storedCoupon);
        assertEquals(CouponValidationStatus.VALID, storedCoupon.getStatus());
        //create request (checking SecurityRequest is mocked) using own platformId
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, federationId, couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier(), null);
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
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any())).thenReturn(new HashSet<>());
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, federationId, PLATFORM_ID, null);
        barteralAccessManagementService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getCouponFailNoCoreBTMConnection() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        ReflectionTestUtils.setField(barteralAccessManagementService, "btmCoreAddress", "Wrong value");
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, federationId, PLATFORM_ID, null);
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
        CouponRequest couponRequest = new CouponRequest(Coupon.Type.DISCRETE, federationId, PLATFORM_ID, null);
        barteralAccessManagementService.getCoupon(couponRequest);
    }


}
