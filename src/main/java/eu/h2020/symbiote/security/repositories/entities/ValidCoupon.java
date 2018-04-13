package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Coupon;
import org.springframework.data.annotation.Id;

public class ValidCoupon {
    @Id
    private final String id;
    private final Coupon coupon;
    private long validity;

    public ValidCoupon(String id, Coupon coupon, long validity) {
        this.id = id;
        this.coupon = coupon;
        this.validity = validity;
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
