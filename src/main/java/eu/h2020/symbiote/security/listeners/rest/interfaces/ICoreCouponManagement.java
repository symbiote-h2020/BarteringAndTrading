package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Profile("core")
public interface ICoreCouponManagement {

    @PostMapping(value = SecurityConstants.BTM_REGISTER_COUPON, consumes = "application/json")
    ResponseEntity<String> registerCoupon(@RequestBody Coupon coupon);

    @PostMapping(value = SecurityConstants.BTM_IS_COUPON_VALID, consumes = "application/json")
    ResponseEntity<String> isCouponValid(@RequestBody Coupon coupon);

    @PostMapping(value = SecurityConstants.BTM_CONSUME_COUPON, consumes = "application/json")
    ResponseEntity<String> consumeCoupon(@RequestBody Coupon coupon);

    @PostMapping(value = SecurityConstants.BTM_CLEANUP_COUPONS, consumes = "application/json")
    ResponseEntity<String> cleanupConsumedCoupons(@RequestBody long timestamp);


}
