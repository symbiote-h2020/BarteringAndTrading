package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Coupon;
import org.springframework.data.annotation.Id;

public class ValidCoupon {
    @Id
    private final String id;
    private final Coupon coupon;
    private Long validity;

    public ValidCoupon(Coupon coupon) {
        this.id = coupon.getId();
        this.coupon = coupon;
        this.validity = (Long) coupon.getClaims().get("val");
    }

    public Long getValidity() {
        return validity;
    }

    public void setValidity(Long validity) {
        this.validity = validity;
    }

    public Coupon getCoupon() {
        return coupon;
    }
}
