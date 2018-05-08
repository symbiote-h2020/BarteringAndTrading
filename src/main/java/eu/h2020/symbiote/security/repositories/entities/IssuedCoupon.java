package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Coupon;
import org.springframework.data.annotation.Id;

public class IssuedCoupon {
    @Id
    private final String id;
    private final Coupon coupon;
    private final String issuer;
    private long validity;
    private Status status;

    public IssuedCoupon(String id, Coupon coupon, String issuer, long validity, Status status) {
        this.id = id;
        this.coupon = coupon;
        this.issuer = issuer;
        this.validity = validity;
        this.status = status;
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

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getId() {
        return id;
    }

    public enum Status {
        VALID,
        CONSUMED,
        REVOKED
    }
}
