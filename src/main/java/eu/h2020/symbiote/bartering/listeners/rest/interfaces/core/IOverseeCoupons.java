package eu.h2020.symbiote.bartering.listeners.rest.interfaces.core;

import eu.h2020.symbiote.bartering.dto.FilterRequest;
import eu.h2020.symbiote.bartering.dto.FilterResponse;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.List;

@Profile("core")
public interface IOverseeCoupons {

    @PostMapping(value = SecurityConstants.BTM_REGISTER_COUPON)
    ResponseEntity<String> registerCoupon(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString);

    @PostMapping(value = SecurityConstants.BTM_IS_COUPON_VALID)
    ResponseEntity<CouponValidity> isCouponValid(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString);

    @PostMapping(value = SecurityConstants.BTM_CONSUME_COUPON)
    ResponseEntity<String> consumeCoupon(
            @RequestHeader HttpHeaders httpHeaders,
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString);

    @PostMapping(value = SecurityConstants.BTM_CLEANUP_COUPONS)
    ResponseEntity<Integer> cleanupConsumedCoupons(@RequestBody long timestamp);

    @PostMapping(value = "/couponusage")
    ResponseEntity<List<FilterResponse>> listCouponUsage(@RequestBody FilterRequest filter) throws ValidationException;
}
