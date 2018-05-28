package eu.h2020.symbiote.bartering.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Profile("core")
public interface ICoreCouponManagement {

    @PostMapping(value = SecurityConstants.BTM_REGISTER_COUPON)
    ResponseEntity<String> registerCoupon(@RequestBody String couponString);

    @PostMapping(value = SecurityConstants.BTM_IS_COUPON_VALID)
    ResponseEntity<CouponValidity> isCouponValid(@RequestBody String couponString);

    @PostMapping(value = SecurityConstants.BTM_CONSUME_COUPON)
    ResponseEntity<String> consumeCoupon(@RequestBody String couponString);

    @PostMapping(value = SecurityConstants.BTM_CLEANUP_COUPONS)
    ResponseEntity<Integer> cleanupConsumedCoupons(@RequestBody long timestamp);


}
