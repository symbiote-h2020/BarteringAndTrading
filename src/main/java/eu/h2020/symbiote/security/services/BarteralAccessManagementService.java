package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.BTMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.repositories.FederationsRepository;
import eu.h2020.symbiote.security.repositories.StoredCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Spring service used to provide token related functionality of the BAT.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("platform")
@Service
public class BarteralAccessManagementService {
    private static final String BTM_SUFFIX = "/btm";
    private static Log log = LogFactory.getLog(BarteralAccessManagementService.class);
    private final String coreInterfaceAddress;
    private final String btmCoreAddress;
    private final StoredCouponsRepository storedCouponsRepository;
    private final FederationsRepository federationsRepository;
    private final CouponIssuer couponIssuer;
    private final ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private final CertificationAuthorityHelper certificationAuthorityHelper;


    @Autowired
    public BarteralAccessManagementService(CouponIssuer couponIssuer,
                                           @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                                           StoredCouponsRepository storedCouponsRepository,
                                           FederationsRepository federationsRepository,
                                           ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                           CertificationAuthorityHelper certificationAuthorityHelper) {
        this.coreInterfaceAddress = coreInterfaceAddress;
        this.btmCoreAddress = coreInterfaceAddress.endsWith("/aam") ? coreInterfaceAddress.substring(0, coreInterfaceAddress.length() - 4) + BTM_SUFFIX : coreInterfaceAddress + BTM_SUFFIX;
        this.couponIssuer = couponIssuer;
        this.storedCouponsRepository = storedCouponsRepository;
        this.federationsRepository = federationsRepository;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
    }

    public boolean authorizeBarteralAccess(BarteralAccessRequest barteralAccessRequest) throws
            BTMException,
            AAMException,
            ValidationException,
            SecurityHandlerException,
            InvalidArgumentsException {
        // check if we are in provided federation
        if (!federationsRepository.exists(barteralAccessRequest.getFederationId())) {
            throw new InvalidArgumentsException("Provided federation doesn't exist");
        }
        Federation federation = federationsRepository.findOne(barteralAccessRequest.getFederationId());
        Set<String> federationMembersIds = federation.getMembers().stream()
                .map(FederationMember::getPlatformId)
                .collect(Collectors.toSet());
        if (!federationMembersIds.contains(barteralAccessRequest.getClientPlatform())
                || !federationMembersIds.contains(certificationAuthorityHelper.getBTMPlatformInstanceIdentifier())) {
            throw new ValidationException("Local platform or clients platform is not in proveded federation");
        }

        BTMClient coreBtmClient = new BTMClient(btmCoreAddress);
        AAMClient aamClient = new AAMClient(coreInterfaceAddress);
        //get clients btm address
        Map<String, AAM> availableAAMs = aamClient.getAvailableAAMs().getAvailableAAMs();
        if (!availableAAMs.containsKey(barteralAccessRequest.getClientPlatform())) {
            throw new BTMException("Clients platform is not registered in CoreAAM.");
        }
        String clientPlatformAddress = availableAAMs.get(barteralAccessRequest.getClientPlatform()).getAamAddress();
        String clientBtmAddress = clientPlatformAddress.endsWith("/aam") ? clientPlatformAddress.substring(0, clientPlatformAddress.length() - 4) + BTM_SUFFIX : clientPlatformAddress + BTM_SUFFIX;
        //ask for new coupon
        BTMClient btmClient = new BTMClient(clientBtmAddress);
        //generate coupon Request
        CouponRequest couponRequest = new CouponRequest(barteralAccessRequest.getCouponType(),
                    certificationAuthorityHelper.getBTMPlatformInstanceIdentifier(),
                    componentSecurityHandlerProvider.getComponentSecurityHandler().generateSecurityRequestUsingLocalCredentials());

        String receivedCouponString = btmClient.getCoupon(couponRequest);
        Claims claims = JWTEngine.getClaims(receivedCouponString);
        //if received our coupon but not validated properly
        if (claims.getIssuer().equals(certificationAuthorityHelper.getBTMPlatformInstanceIdentifier())
                && !coreBtmClient.consumeCoupon(receivedCouponString)) {
            return false;
        }
        //if received foreign coupon for bartering
        if (!claims.getIssuer().equals(certificationAuthorityHelper.getBTMPlatformInstanceIdentifier())) {
            // validate coupon in core
            CouponValidity couponValidity = coreBtmClient.isCouponValid(receivedCouponString);
            // TODO: validate B&T
            if (!couponValidity.getStatus().equals(CouponValidationStatus.VALID))
                return false;
            log.info("Received and saved new valid coupon from: " + barteralAccessRequest.getClientPlatform());
            storedCouponsRepository.save(new StoredCoupon(new Coupon(receivedCouponString)));
        }
        return true;
    }

    public String getCoupon(CouponRequest couponRequest) throws ValidationException, BTMException, JWTCreationException {
        try {
            // building CHTAP access policy
            Map<String, IAccessPolicy> componentHomeTokenAPs = new HashMap<>();
            String componentHTPolicyId = "btmPolicy";
            SingleTokenAccessPolicySpecifier policySpecifier =
                    new SingleTokenAccessPolicySpecifier("btm", couponRequest.getPlatformId());
            componentHomeTokenAPs.put(componentHTPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(policySpecifier));

            if (componentSecurityHandlerProvider
                    .getComponentSecurityHandler()
                    .getSatisfiedPoliciesIdentifiers(componentHomeTokenAPs, couponRequest.getSecurityRequest())
                    .size() != 1) {
                throw new ValidationException(ValidationException.VALIDATION_ERROR_OCCURRED);
            }
            // create BTM client connected to core for future validation/coupon registration
            BTMClient btmClient = new BTMClient(btmCoreAddress);

            //search for all stored coupons
            HashSet<StoredCoupon> storedCouponHashSet = storedCouponsRepository.findAllByIssuerAndType(couponRequest.getPlatformId(), couponRequest.getCouponType());
            for (StoredCoupon storedCoupon : storedCouponHashSet) {
                //find all VALID stored coupons and check their validity again
                if (storedCoupon.getStatus().equals(CouponValidationStatus.VALID)) {
                    // validate coupon in core
                    CouponValidity couponValidity = btmClient.isCouponValid(storedCoupon.getCouponString());
                    // if core confirms Validity of the coupon - return it
                    if (couponValidity.getStatus().equals(CouponValidationStatus.VALID)) {
                        return storedCoupon.getCouponString();
                    }
                    //else update db
                    storedCoupon.setStatus(couponValidity.getStatus());
                    storedCouponsRepository.save(storedCoupon);
                }
            }
            // if no valid coupon found - create new for bartering
            Coupon coupon = couponIssuer.getCoupon(couponRequest.getCouponType());
            //register coupon in core
            if (!btmClient.registerCoupon(coupon.getCoupon())) {
                storedCouponsRepository.delete(coupon.getId());
                throw new BTMException("Couldn't register new coupon.");
            }
            return coupon.getCoupon();

        } catch (InvalidArgumentsException e) {
            log.error(e.getMessage());
            throw new BTMException(e.getMessage());
        }
    }

}
