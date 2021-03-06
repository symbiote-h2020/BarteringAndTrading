package eu.h2020.symbiote.bartering.services;

import eu.h2020.symbiote.bartering.communication.BTMClient;
import eu.h2020.symbiote.bartering.communication.CoreBTMClient;
import eu.h2020.symbiote.bartering.config.AppConfig;
import eu.h2020.symbiote.bartering.config.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.bartering.repositories.CouponsWallet;
import eu.h2020.symbiote.bartering.repositories.FederationsRepository;
import eu.h2020.symbiote.bartering.repositories.entities.CouponEntity;
import eu.h2020.symbiote.bartering.services.helpers.CouponIssuer;
import eu.h2020.symbiote.model.mim.Federation;
import eu.h2020.symbiote.model.mim.FederationMember;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
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
 * Spring service used to provide bartered access authorization codes.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("platform")
@Service
public class BarteredAccessManagementService {
    private static final String BTM_SUFFIX = "/btm";
    private static Log log = LogFactory.getLog(BarteredAccessManagementService.class);

    private final String coreBTMAddress;
    private final ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private final CouponIssuer couponIssuer;
    private final CouponsWallet couponsWallet;
    private final FederationsRepository federationsRepository;
    private final AppConfig appConfig;

    @Autowired
    public BarteredAccessManagementService(CouponIssuer couponIssuer,
                                           @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                                           CouponsWallet couponsWallet,
                                           FederationsRepository federationsRepository,
                                           ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                           AppConfig appConfig) {
        this.appConfig = appConfig;
        this.coreBTMAddress = (coreInterfaceAddress.endsWith("/aam")
                ? coreInterfaceAddress.substring(0, coreInterfaceAddress.length() - 4)
                : coreInterfaceAddress)
                + BTM_SUFFIX;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.couponIssuer = couponIssuer;
        this.couponsWallet = couponsWallet;
        this.federationsRepository = federationsRepository;
    }

    /**
     * Check, if user/actor from federated platform can access resource.
     *
     * @param barteredAccessRequest containing information about user, federation and resource to be accessed
     * @return true if access should be granted
     * @throws BTMException
     * @throws ValidationException
     * @throws SecurityHandlerException
     * @throws InvalidArgumentsException
     */
    public boolean authorizeBarteredAccess(BarteredAccessRequest barteredAccessRequest) throws
            BTMException,
            ValidationException,
            SecurityHandlerException,
            InvalidArgumentsException,
            WrongCredentialsException {
        // check if both client requesting access and this platform is in the given federation
        log.debug("check if both client requesting access and this platform is in the given federation");
        if (!federationsRepository.exists(barteredAccessRequest.getFederationId())) {
            throw new InvalidArgumentsException("Provided federation doesn't exist");
        }
        Federation federation = federationsRepository.findOne(barteredAccessRequest.getFederationId());
        Set<String> federationMembersIds = federation.getMembers().stream()
                .map(FederationMember::getPlatformId)
                .collect(Collectors.toSet());
        if (!federationMembersIds.contains(barteredAccessRequest.getClientPlatform())
                || !federationMembersIds.contains(appConfig.getPlatformIdentifier())) {
            throw new ValidationException("Local platform or clients platform is not in provided federation");
        }

        //get clients btm address
        log.debug("get clients btm address");

        Map<String, AAM> availableAAMs = componentSecurityHandlerProvider.getComponentSecurityHandler().getSecurityHandler().getAvailableAAMs();
        if (!availableAAMs.containsKey(barteredAccessRequest.getClientPlatform())) {
            throw new BTMException("Clients platform is not registered in CoreAAM.");
        }


        String clientPlatformAddress = availableAAMs.get(barteredAccessRequest.getClientPlatform()).getAamAddress();
        String clientBtmAddress = (clientPlatformAddress.endsWith("/aam")
                ? clientPlatformAddress.substring(0, clientPlatformAddress.length() - 4)
                : clientPlatformAddress)
                + BTM_SUFFIX;

        // ask for my own coupon
        log.debug("ask for my own coupon");
        BTMClient remotePlatformBTMClient = new BTMClient(clientBtmAddress);
        //generate coupon Request
        CouponRequest couponRequest = new CouponRequest(barteredAccessRequest.getCouponType(),
                barteredAccessRequest.getFederationId(),
                appConfig.getPlatformIdentifier(),
                componentSecurityHandlerProvider.getComponentSecurityHandler().generateSecurityRequestUsingLocalCredentials());

        String receivedCouponString = remotePlatformBTMClient.getCoupon(couponRequest);
        Claims claims = JWTEngine.getClaims(receivedCouponString);
        // check, if coupon is for proper federation Id
        log.debug("check, if coupon is for proper federation Id");
        if (!claims.get(SecurityConstants.CLAIM_NAME_FEDERATION_ID, String.class).equals(barteredAccessRequest.getFederationId())) {
            log.error("CouponEntity does not contain proper federation Id.");
            return false;
        }
        // if we have received our own coupon but it was already invalidated (we couldn't consume it anymore)
        log.debug("if we have received our own coupon but it was already invalidated (we couldn't consume it anymore)");
        CoreBTMClient coreBTMClient = new CoreBTMClient(this.coreBTMAddress, this.componentSecurityHandlerProvider.getComponentSecurityHandler());
        if (claims.getIssuer().equals(appConfig.getPlatformIdentifier())
                && !coreBTMClient.consumeCoupon(receivedCouponString)) {
            //TODO shouldn't we pass the resource id for which we want to consume this coupon?
            log.error("Core did not confirmed coupon consumption.");
            return false;
        }
        // if we have received foreign coupon for bartering
        log.debug("if we have received foreign coupon for bartering");
        if (!claims.getIssuer().equals(appConfig.getPlatformIdentifier())) {
            // validate coupon in core
            CouponValidity couponValidity = coreBTMClient.isCouponValid(receivedCouponString);
            // TODO: validate B&T deal
            if (!couponValidity.getStatus().equals(CouponValidationStatus.VALID)) {
                log.error("CouponEntity received for bartering did not pass validation in Core.");
                return false;
            }
            log.info("Received and saved new valid coupon from: " + barteredAccessRequest.getClientPlatform());
            couponsWallet.save(new CouponEntity(new Coupon(receivedCouponString)));
            // TODO don't we need to issue our own coupon and report to the CoreBTM that is was consumed?
        }
        return true;
    }

    /**
     * Returns coupon to grant local user access to the federated resource in other platform.
     *
     * @param couponRequest containing information about the resource, platform etc.
     * @return coupon issued by federated platform owning the resource or local coupon for the exchange
     * @throws ValidationException  component requesting coupon is not entitled to get it
     * @throws BTMException
     * @throws JWTCreationException could not create coupon
     */
    public String getCoupon(CouponRequest couponRequest) throws
            ValidationException,
            BTMException,
            JWTCreationException,
            WrongCredentialsException {
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

            //search for all stored coupons
            HashSet<CouponEntity> couponEntityHashSet = couponsWallet.findAllByIssuerAndTypeAndFederationIdAndStatus(
                    couponRequest.getPlatformId(),
                    couponRequest.getCouponType(),
                    couponRequest.getFederationId(),
                    CouponValidationStatus.VALID);
            log.info("search for all stored coupons: " + couponEntityHashSet.toString());

            CoreBTMClient coreBTMClient = new CoreBTMClient(this.coreBTMAddress, this.componentSecurityHandlerProvider.getComponentSecurityHandler());
            for (CouponEntity couponEntity : couponEntityHashSet) {
                // validate couponEntity in core
                log.debug("validate couponEntity in core");
                CouponValidity couponValidity = coreBTMClient.isCouponValid(couponEntity.getCouponString());
                // if core confirms Validity of the couponEntity - return it
                if (couponValidity.getStatus().equals(CouponValidationStatus.VALID)) {
                    log.debug("core confirms Validity of the couponEntity - return it");
                    return couponEntity.getCouponString();
                }
                //else update db
                couponEntity.setStatus(couponValidity.getStatus());
                couponsWallet.save(couponEntity);
            }
            // if no valid coupon found - create new for bartering
            log.debug("if no valid coupon found - create new for bartering");
            Coupon coupon = couponIssuer.getCoupon(couponRequest.getCouponType(), couponRequest.getFederationId());
            //register coupon in core
            log.debug("register coupon in core");
            if (!coreBTMClient.registerCoupon(coupon.getCoupon())) {
                couponsWallet.delete(coupon.getId());
                throw new BTMException("Couldn't register new coupon.");
            }
            log.debug("return coupon");
            return coupon.getCoupon();

        } catch (InvalidArgumentsException | SecurityHandlerException e) {
            log.error(e.getMessage());
            throw new BTMException(e.getMessage());
        }
    }

}
