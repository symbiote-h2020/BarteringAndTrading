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
    @Indexed
    private Coupon.Type type;
    private Status status;

    public StoredCoupon(Coupon coupon) {
        this.id = coupon.getId();
        this.couponString = coupon.getCoupon();
        this.issuer = coupon.getClaims().getIssuer();
        this.type = coupon.getType();
        this.status = Status.VALID;
    }

    /**
     * Constructor used by MongoDB
     */

    public StoredCoupon() {
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
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

    public Coupon.Type getType() {
        return type;
    }

    public void setType(Coupon.Type type) {
        this.type = type;
    }

    public enum Status {
        VALID,
        CONSUMED,
        REVOKED
    }


}