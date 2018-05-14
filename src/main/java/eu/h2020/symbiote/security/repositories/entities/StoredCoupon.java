package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Coupon;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;

public class StoredCoupon {
    @Id
    private String id;
    private String couponString;
    @Indexed
    private String issuer;
    private long validity;
    private Status status;

    public StoredCoupon(Coupon coupon) {
        this.id = coupon.getId();
        this.couponString = coupon.getCoupon();
        this.issuer = coupon.getClaims().getIssuer();
        this.validity = Long.parseLong(coupon.getClaims().get("val").toString());
        this.status = Status.VALID;
    }

    /**
     * Constructor used by MongoDB
     */

    public StoredCoupon() {
    }

    public void setValidity(long validity) {
        this.validity = validity;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public Long getValidity() {
        return validity;
    }

    public void setValidity(Long validity) {
        this.validity = validity;
    }

    public String getCouponString() {
        return couponString;
    }

    public void setCouponString(String couponString) {
        this.couponString = couponString;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public enum Status {
        VALID,
        CONSUMED,
        REVOKED
    }


}
