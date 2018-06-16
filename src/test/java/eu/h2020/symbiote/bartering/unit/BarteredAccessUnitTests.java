package eu.h2020.symbiote.bartering.unit;

import eu.h2020.symbiote.bartering.AbstractBTMTestSuite;
import eu.h2020.symbiote.bartering.repositories.entities.CouponEntity;
import eu.h2020.symbiote.bartering.services.helpers.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.BTMClient;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.handler.ComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
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

import static eu.h2020.symbiote.security.commons.Coupon.Type;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@TestPropertySource("/service.properties")
public class BarteredAccessUnitTests extends AbstractBTMTestSuite {

    @Autowired
    ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private String BTM_AP_NAME = "btmAPName";
    private String PLATFORM_ID = "testPlatformId";
    private String federationId = "testFederationId";
    private Federation federation;

    private ISecurityHandler mockedSecurityHandler;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        Set<String> set = new HashSet<>();
        set.add(BTM_AP_NAME);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(Mockito.any(), Mockito.any()))
                .thenReturn(set);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler())
                .thenReturn(mockedComponentSecurityHandler);
        mockedSecurityHandler = Mockito.mock(ISecurityHandler.class);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler().getSecurityHandler())
                .thenReturn(mockedSecurityHandler);
        when(mockedSecurityHandler.getAvailableAAMs())
                .thenReturn(new AAMClient(serverAddress + "/test/caam").getAvailableAAMs().getAvailableAAMs());
        ReflectionTestUtils.setField(barteredAccessManagementService, "coreBTMClient", new BTMClient(serverAddress + "/test/btm"));
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
    public void authorizeBarteredAccessSuccessReceivedLocalCoupon() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyPlatformBTM.receivedCouponIssuer = couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier();
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        assertTrue(barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest));
        //no coupon saved in db
        assertEquals(0, couponsWallet.count());
    }

    @Test
    public void authorizeBarteredAccessSuccessReceivedForeignCoupon() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyPlatformBTM.receivedCouponIssuer = dummyPlatformId;
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        assertTrue(barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest));
        //coupon saved in db
        assertEquals(1, couponsWallet.count());
    }

    @Test(expected = InvalidArgumentsException.class)
    public void authorizeBarteredAccessFailNoFederation() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest);
    }

    @Test(expected = ValidationException.class)
    public void authorizeBarteredAccessFailNoLocalPlatformInFederation() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        //remove local platform from federation
        federation.getMembers().remove(1);
        federationsRepository.save(federation);
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest);
    }

    @Test(expected = ValidationException.class)
    public void authorizeBarteredAccessFailNoForeignPlatformInFederation() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        //remove foreign platform from federation
        federation.getMembers().remove(0);
        federationsRepository.save(federation);
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest);
    }

    @Test(expected = SecurityHandlerException.class)
    public void authorizeBarteredAccessFailNoCoreConnection() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {

        federationsRepository.save(federation);
        when(mockedSecurityHandler.getAvailableAAMs()).thenThrow(new SecurityHandlerException(""));
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest);
    }

    @Test(expected = BTMException.class)
    public void authorizeBarteredAccessFailClientsPlatformNotRegistered() throws
            SecurityHandlerException,
            BTMException,
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

        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest("notRegisteredPlatformId", federationId, "resourceId", Type.DISCRETE);
        barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest);
    }

    @Test
    public void authorizeBarteredAccessFailReturnedCouponWithWrongFederationId() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        federation.setId("wrongId");
        federationsRepository.save(federation);
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, "wrongId", "resourceId", Type.DISCRETE);
        assertFalse(barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest));
    }

    @Test(expected = SecurityHandlerException.class)
    public void authorizeBarteredAccessFailSecurityRequestCreation() throws
            SecurityHandlerException,
            ValidationException,
            BTMException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        ComponentSecurityHandler mockedComponentSecurityHandler = Mockito.mock(ComponentSecurityHandler.class);
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials()).thenThrow(new SecurityHandlerException(""));
        when(componentSecurityHandlerProvider.getComponentSecurityHandler()).thenReturn(mockedComponentSecurityHandler);
        when(mockedComponentSecurityHandler.getSecurityHandler())
                .thenReturn(mockedSecurityHandler);
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest);
    }

    @Test
    public void authorizeBarteredAccessFailReceivedLocalCouponNotValid() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyPlatformBTM.receivedCouponIssuer = couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier();
        dummyCoreAAMAndBTM.consumptionStatus = HttpStatus.BAD_REQUEST;
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        assertFalse(barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest));
    }

    @Test
    public void authorizeBarteredAccessFailReceivedForeignCouponNotValid() throws
            SecurityHandlerException,
            BTMException,
            ValidationException,
            InvalidArgumentsException {
        federationsRepository.save(federation);
        dummyCoreAAMAndBTM.couponValidationStatus = CouponValidationStatus.CONSUMED_COUPON;
        BarteredAccessRequest barteredAccessRequest = new BarteredAccessRequest(dummyPlatformId, federationId, "resourceId", Type.DISCRETE);
        assertFalse(barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest));
    }

    @Test
    public void getCouponSuccessReturnedStoredCoupon() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        //put proper VALID coupon into repo
        CouponEntity locallyStoredCouponEntity = new CouponEntity(couponIssuer.getCoupon(Type.DISCRETE, federationId));
        couponsWallet.save(locallyStoredCouponEntity);
        assertEquals(CouponValidationStatus.VALID, locallyStoredCouponEntity.getStatus());
        //create request (checking SecurityRequest is mocked) using own platformId
        CouponRequest couponRequest = new CouponRequest(Type.DISCRETE, federationId, couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier(), null);
        String couponString = barteredAccessManagementService.getCoupon(couponRequest);
        //returned coupon should not be empty
        assertNotNull(couponString);
        eu.h2020.symbiote.security.commons.Coupon coupon = new eu.h2020.symbiote.security.commons.Coupon(couponString);
        //returned coupon should have proper type
        assertEquals(Type.DISCRETE, coupon.getType());
        //returned coupon should be different than those stored
        assertEquals(locallyStoredCouponEntity.getId(), coupon.getId());
    }

    @Test
    public void getCouponSuccessNoStoredCouponsAndReturnedNewCoupon() throws
            ValidationException,
            BTMException,
            JWTCreationException {
        //check if repo is empty
        assertEquals(0, couponsWallet.count());
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Type.DISCRETE, federationId, PLATFORM_ID, null);
        String couponString = barteredAccessManagementService.getCoupon(couponRequest);
        //returned coupon should not be empty
        assertNotNull(couponString);
        eu.h2020.symbiote.security.commons.Coupon coupon = new eu.h2020.symbiote.security.commons.Coupon(couponString);
        //returned coupon should have proper type
        assertEquals(Type.DISCRETE, coupon.getType());
    }

    @Test
    public void getCouponSuccessStoredCouponsUpdatedAndReturnedNewCoupon() throws
            ValidationException,
            BTMException,
            JWTCreationException {
        // change dummy Core BTM to return proper validation status
        dummyCoreAAMAndBTM.couponValidationStatus = CouponValidationStatus.CONSUMED_COUPON;
        //put proper VALID coupon into repo
        CouponEntity locallyStoredCouponEntity = new CouponEntity(couponIssuer.getCoupon(Type.DISCRETE, federationId));
        couponsWallet.save(locallyStoredCouponEntity);
        assertEquals(CouponValidationStatus.VALID, locallyStoredCouponEntity.getStatus());
        //create request (checking SecurityRequest is mocked) using own platformId
        CouponRequest couponRequest = new CouponRequest(Type.DISCRETE, federationId, couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier(), null);
        String couponString = barteredAccessManagementService.getCoupon(couponRequest);
        //returned coupon should not be empty
        assertNotNull(couponString);
        eu.h2020.symbiote.security.commons.Coupon coupon = new eu.h2020.symbiote.security.commons.Coupon(couponString);
        //returned coupon should have proper type
        assertEquals(Type.DISCRETE, coupon.getType());
        //returned coupon should be different than those stored
        assertNotEquals(locallyStoredCouponEntity.getId(), coupon.getId());
        //stored coupon status should be changed
        assertEquals(CouponValidationStatus.CONSUMED_COUPON, couponsWallet.findOne(locallyStoredCouponEntity.getId()).getStatus());
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
        CouponRequest couponRequest = new CouponRequest(Type.DISCRETE, federationId, PLATFORM_ID, null);
        barteredAccessManagementService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getCouponFailNoCoreBTMConnection() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        ReflectionTestUtils.setField(barteredAccessManagementService, "coreBTMClient", new BTMClient(serverAddress + "/wrong_btm"));
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Type.DISCRETE, federationId, PLATFORM_ID, null);
        barteredAccessManagementService.getCoupon(couponRequest);
    }

    @Test(expected = BTMException.class)
    public void getCouponFailNewCouponRegistrationError() throws
            JWTCreationException,
            BTMException,
            ValidationException {
        // change dummy Core BTM to return proper registrationStatus
        dummyCoreAAMAndBTM.registrationStatus = HttpStatus.BAD_REQUEST;
        //create request (checking SecurityRequest is mocked)
        CouponRequest couponRequest = new CouponRequest(Type.DISCRETE, federationId, PLATFORM_ID, null);
        barteredAccessManagementService.getCoupon(couponRequest);
    }


}
