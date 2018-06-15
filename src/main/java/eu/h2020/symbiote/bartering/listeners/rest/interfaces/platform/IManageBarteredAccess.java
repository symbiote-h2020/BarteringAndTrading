package eu.h2020.symbiote.bartering.listeners.rest.interfaces.platform;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes services allowing SymbIoTe components to acquire coupons
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public interface IManageBarteredAccess {
    /**
     * @param couponRequest Request containing information about platform, type of requesting coupon and SecurityRequest for BTM authorization
     * @return CouponEntity used to access resources offered in SymbIoTe
     */
    @PostMapping(value = SecurityConstants.BTM_GET_COUPON)
    ResponseEntity<String> getCoupon(@RequestBody CouponRequest couponRequest);

    /**
     * @param barteredAccessRequest Request containing information about client trying to get assess to the resource, resourceId and type of access (temporal, discrete)
     * @return HTTP Status containing information about the result of the operation (OK, INTERNAL_SERVER_ERROR, BAD_REQUEST etc.)
     */
    @PostMapping(value = SecurityConstants.BTM_AUTHORIZE_BARTERAL_ACCESS)
    ResponseEntity<String> authorizeBarteredAccess(@RequestBody BarteredAccessRequest barteredAccessRequest);
}
