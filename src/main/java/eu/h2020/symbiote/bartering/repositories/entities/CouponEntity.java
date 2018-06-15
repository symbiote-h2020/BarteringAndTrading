package eu.h2020.symbiote.bartering.repositories.entities;

import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceConstructor;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * CouponEntity stored in a Platform BTM coupons wallet.
 */
@Document
public class CouponEntity {
    @Id
    private final String id;
    private final String couponString;
    @Indexed
    private final String issuer;
    @Indexed
    private final eu.h2020.symbiote.security.commons.Coupon.Type type;
    private final String federationId;

    private CouponValidationStatus status;

    @PersistenceConstructor
    public CouponEntity(String id,
                        String couponString,
                        String issuer,
                        String federationId,
                        eu.h2020.symbiote.security.commons.Coupon.Type type,
                        CouponValidationStatus status) {
        this.id = id;
        this.couponString = couponString;
        this.issuer = issuer;
        this.federationId = federationId;
        this.type = type;
        this.status = status;
    }

    @PersistenceConstructor
    public CouponEntity(eu.h2020.symbiote.security.commons.Coupon coupon) {
        this(coupon.getId(),
                coupon.getCoupon(),
                coupon.getClaims().getIssuer(),
                coupon.getClaims().get("fedId", String.class),
                coupon.getType(),
                CouponValidationStatus.VALID);
    }

    public CouponValidationStatus getStatus() {
        return status;
    }

    public void setStatus(CouponValidationStatus status) {
        this.status = status;
    }

    public String getCouponString() {
        return couponString;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getId() {
        return id;
    }

    public eu.h2020.symbiote.security.commons.Coupon.Type getType() {
        return type;
    }

    public String getFederationId() {
        return federationId;
    }
}
