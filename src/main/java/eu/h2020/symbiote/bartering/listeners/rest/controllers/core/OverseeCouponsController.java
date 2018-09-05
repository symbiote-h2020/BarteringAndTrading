package eu.h2020.symbiote.bartering.listeners.rest.controllers.core;

import eu.h2020.symbiote.bartering.config.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.bartering.listeners.rest.interfaces.core.IOverseeCoupons;
import eu.h2020.symbiote.bartering.repositories.TrustRepository;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
import eu.h2020.symbiote.bartering.services.IssuedCouponsRegistryManagementService;
import eu.h2020.symbiote.barteringAndTrading.FilterRequest;
import eu.h2020.symbiote.barteringAndTrading.FilterResponse;
import eu.h2020.symbiote.cloud.trust.model.TrustEntry;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import io.jsonwebtoken.Claims;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.CertificateException;
import java.util.*;

/**
 * Spring controller to handle HTTPS requests associated with overseeing symbiote coupons in the CoreBTM.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
@Profile("core")
@RestController
public class OverseeCouponsController implements IOverseeCoupons {


    private static Log log = LogFactory.getLog(OverseeCouponsController.class);
    private IssuedCouponsRegistryManagementService couponManagementService;
    private ComponentSecurityHandlerProvider componentSecurityHandlerProvider;

    @Value("${trust.entity.threshold}")
    private Double trustEntityThreshold ;

    @Autowired
    private TrustRepository trustRepository;

    @Autowired
    public OverseeCouponsController(IssuedCouponsRegistryManagementService couponManagementService,
                                    ComponentSecurityHandlerProvider componentSecurityHandlerProvider) {
        this.couponManagementService = couponManagementService;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
    }

    @Override
    @ApiOperation(value = "Register coupon in the Core BTM.")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon was malformed"),
            @ApiResponse(code = 401, message = "Received coupon was not valid"),
            @ApiResponse(code = 500, message = "Internal server error occurred (DB error, connection error)")})
    public ResponseEntity<String> registerCoupon(
            @RequestHeader @ApiParam(value = "Security headers", required = true) HttpHeaders httpHeaders,
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString) {
        // validate the client
        HttpStatus validationHttpStatus = validateClientCredentials(httpHeaders);
        if (!validationHttpStatus.equals(HttpStatus.OK))
            return getResponseWithSecurityHeaders(null, validationHttpStatus);
        try {
            if (couponManagementService.registerCoupon(new Coupon(couponString))) {
                return getResponseWithSecurityHeaders(null, HttpStatus.OK);
            }
            return getResponseWithSecurityHeaders(null, HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (SecurityHandlerException | MalformedJWTException | ValidationException | BTMException e) {
            log.error(e.getMessage());
            return getResponseWithSecurityHeaders(e.getErrorMessage(), e.getStatusCode());
        } catch (CertificateException e) {
            log.error(e.getMessage());
            return getResponseWithSecurityHeaders(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    @ApiOperation(value = "Consume coupon in the Core BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon didn't pass validation")})
    public ResponseEntity<String> consumeCoupon(
            @RequestHeader @ApiParam(value = "Security headers", required = true) HttpHeaders httpHeaders,
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString) {
        HttpStatus validationHttpStatus = validateClientCredentials(httpHeaders);
        if (!validationHttpStatus.equals(HttpStatus.OK))
            return getResponseWithSecurityHeaders(null, validationHttpStatus);

      /*  // check if client is over threshold
        if (!isThresholdSuccessfullyExceeded(httpHeaders)){
            return getResponseWithSecurityHeaders(null, HttpStatus.PRECONDITION_FAILED);
        }*/

        try {
            CouponValidationStatus couponValidationStatus = couponManagementService.consumeCoupon(new Coupon(couponString));
            if (couponValidationStatus == CouponValidationStatus.VALID) {
                return getResponseWithSecurityHeaders(null, HttpStatus.OK);
            } else {
                return getResponseWithSecurityHeaders(null, HttpStatus.BAD_REQUEST);
            }
        } catch (ValidationException e) {
            log.error("Received coupon was malformed");
            return getResponseWithSecurityHeaders(null, HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    @ApiOperation(value = "CouponEntity validation in Core BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon was malformed")})
    public ResponseEntity<CouponValidity> isCouponValid(
            @RequestHeader @ApiParam(value = "Security headers", required = true) HttpHeaders httpHeaders,
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString) {
        // validate the client
        HttpStatus validationHttpStatus = validateClientCredentials(httpHeaders);
        if (!validationHttpStatus.equals(HttpStatus.OK))
            return getResponseWithSecurityHeaders(null, validationHttpStatus);
        try {
            CouponValidity couponValidity = couponManagementService.isCouponValid(new Coupon(couponString));
            return getResponseWithSecurityHeaders(couponValidity, HttpStatus.OK);
        } catch (ValidationException e) {
            log.error("Received coupon was malformed");
            return getResponseWithSecurityHeaders(null, HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    @ApiOperation(value = "Cleanup all consumed coupons before provided timestamp")
    public ResponseEntity<Integer> cleanupConsumedCoupons(@RequestBody long timestamp) {
        //TODO who should be able to do that?
        int removed = couponManagementService.cleanupConsumedCoupons(timestamp);
        return new ResponseEntity<>(removed, HttpStatus.OK);
    }

    private HttpStatus validateClientCredentials(@RequestHeader HttpHeaders httpHeaders) {
        try {
            SecurityRequest securityRequest;
            try {
                securityRequest = new SecurityRequest(httpHeaders.toSingleValueMap());
            } catch (InvalidArgumentsException e) {
                // cause empty map causes exception
                return HttpStatus.UNAUTHORIZED;
            }
            JWTClaims claims = JWTEngine.getClaimsFromToken(securityRequest.getSecurityCredentials().iterator().next().getToken());
            // building CHTAP access policy basing on platform found in ISS of security request token
            Map<String, IAccessPolicy> componentHomeTokenAPs = new HashMap<>();
            String componentHTPolicyId = "btmAccessPolicy";
            SingleTokenAccessPolicySpecifier policySpecifier =
                    new SingleTokenAccessPolicySpecifier("btm", claims.getIss());
            componentHomeTokenAPs.put(componentHTPolicyId, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(policySpecifier));

            if (componentSecurityHandlerProvider
                    .getComponentSecurityHandler()
                    .getSatisfiedPoliciesIdentifiers(componentHomeTokenAPs, securityRequest)
                    .size() != 1) {
                log.error("Received security request is not passing Core BTM Access Policy.");
                return HttpStatus.UNAUTHORIZED;
            }
        } catch (InvalidArgumentsException | MalformedJWTException e) {
            log.error("Received security request is malformed: " + e.getMessage());
            return HttpStatus.BAD_REQUEST;
        }
        return HttpStatus.OK;
    }

    private <T> ResponseEntity<T> getResponseWithSecurityHeaders(T body, HttpStatus httpStatus) {
        try {
            // prepare response
            HttpHeaders responseHttpHeaders = new HttpHeaders();
            responseHttpHeaders.add(SecurityConstants.SECURITY_RESPONSE_HEADER, componentSecurityHandlerProvider.getComponentSecurityHandler().generateServiceResponse());
            if (body == null)
                new ResponseEntity(responseHttpHeaders, httpStatus);
            return new ResponseEntity<>(body, responseHttpHeaders, httpStatus);
        } catch (SecurityHandlerException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    @ApiOperation(value = "List used coupons")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received request was malformed")})
    public ResponseEntity<List<FilterResponse>> listCouponUsage(@RequestBody FilterRequest request)
            throws ValidationException {
        if (!request.isValidRequest())
            return getResponseWithSecurityHeaders(null, HttpStatus.BAD_REQUEST);

        List<FilterResponse> list = new ArrayList<>();
        Set<AccountingCoupon> set = couponManagementService.getCouponStats(request);

        for (AccountingCoupon ac : set){
            boolean addIt = false;

            // match federation id
            if(request.getFederationId() != null) {
                Claims claims = JWTEngine.getClaims(ac.getCouponString());
                if (claims.get(SecurityConstants.CLAIM_NAME_FEDERATION_ID,
                        String.class).equals(request.federationId)) {
                    addIt = true;
                }
            }
            else {
                addIt = true;
            }

            // add it to returning list
            if (addIt){
                list.add(new FilterResponse(
                        ac.getId(),
                        ac.getIssuer(),
                        request.beginTimestamp!=null?
                                ac.getNumberOfUsedTimeFiltered(request.beginTimestamp, request.endTimestamp) :
                                ac.getUsagesCounter()
                ));
            }
        }

        return getResponseWithSecurityHeaders(list, HttpStatus.OK);
    }

    private boolean isThresholdSuccessfullyExceeded(@RequestHeader HttpHeaders httpHeaders){
        try {
            SecurityRequest securityRequest;
            securityRequest = new SecurityRequest(httpHeaders.toSingleValueMap());
            JWTClaims claims = JWTEngine.getClaimsFromToken(securityRequest.getSecurityCredentials().iterator().next().getToken());

            TrustEntry te = trustRepository.getPREntryByPlatformId(claims.getIss());

            if (te != null && te.getValue() >= trustEntityThreshold ){
                return true;
            }
        } catch (InvalidArgumentsException e) {}
        catch (MalformedJWTException e) {}

        return false;
    }


}
