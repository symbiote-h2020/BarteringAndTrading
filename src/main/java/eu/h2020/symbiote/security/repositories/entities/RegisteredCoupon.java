package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.springframework.data.annotation.Id;

public class RegisteredCoupon {

    @Id
    private String id;
    private String couponString;
    private String issuer;
    private long validity;
    private Coupon.Type type;
    private long usages;
    private long firstUseTimestamp;
    private long lastConsumptionTimestamp;
    private StoredCoupon.Status status;

    /**
     * for mongo usage
     */
    public RegisteredCoupon() {

    }

    public RegisteredCoupon(String couponString) throws
            MalformedJWTException,
            ValidationException {
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        this.id = createIdFromNotification(claims.getJti(), claims.getIss());
        this.couponString = couponString;
        this.issuer = claims.getIss();
        this.validity = Long.parseLong(claims.getVal());
        this.type = new Coupon(couponString).getType();
        this.usages = 0;
        this.firstUseTimestamp = 0;
        this.lastConsumptionTimestamp = 0;
        this.status = StoredCoupon.Status.VALID;

    }

    public static String createIdFromNotification(String jti, String iss) {
        return jti + CryptoHelper.FIELDS_DELIMITER + iss;
    }

    public long getValidity() {
        return validity;
    }

    public Coupon.Type getType() {
        return type;
    }

    public long getUsages() {
        return usages;
    }

    public void setUsages(long usages) {
        this.usages = usages;
    }

    public long getFirstUseTimestamp() {
        return firstUseTimestamp;
    }

    public void setFirstUseTimestamp(long firstUseTimestamp) {
        this.firstUseTimestamp = firstUseTimestamp;
    }

    public long getLastConsumptionTimestamp() {
        return lastConsumptionTimestamp;
    }

    public void setLastConsumptionTimestamp(long lastConsumptionTimestamp) {
        this.lastConsumptionTimestamp = lastConsumptionTimestamp;
    }

    public StoredCoupon.Status getStatus() {
        return status;
    }

    public void setStatus(StoredCoupon.Status status) {
        this.status = status;
    }

    public String getId() {
        return id;
    }

    public String getCouponString() {
        return couponString;
    }

    public String getIssuer() {
        return issuer;
    }
}
