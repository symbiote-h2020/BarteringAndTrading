package eu.h2020.symbiote.bartering.repositories.entities;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.ArrayList;
import java.util.List;

/**
 * CouponEntity stored in the Core BTM registry along with its consumption details.
 */
@Document
public class AccountingCoupon {

    @Id
    private final String id;
    private final String couponString;
    private final String issuer;
    private final Coupon.Type type;

    /**
     * can be either number of discrete usagesCounter or a period in seconds designating how long should an activated coupon be valid for.
     */
    private final long maximumAllowedUsage;

    /**
     * discrete coupon usagesCounter counter
     */
    private long usagesCounter;

    /**
     * required to get usage history
     */
    private List<Long> useTimestamp;

    /**
     * required to evaluate a timed coupon
     */
    private long firstUseTimestamp;
    private long lastConsumptionTimestamp;

    /**
     * last coupon evaluation status
     */
    private CouponValidationStatus status;

    public AccountingCoupon(String couponString) throws
            MalformedJWTException,
            ValidationException {
        JWTClaims claims = JWTEngine.getClaimsFromToken(couponString);
        this.id = createIdFromNotification(claims.getJti(), claims.getIss());
        this.couponString = couponString;
        this.issuer = claims.getIss();
        this.maximumAllowedUsage = Long.parseLong(claims.getVal());
        this.type = new Coupon(couponString).getType();
        this.usagesCounter = 0;
        this.firstUseTimestamp = 0;
        this.lastConsumptionTimestamp = 0;
        this.status = CouponValidationStatus.VALID;

        this.useTimestamp=new ArrayList<>();

    }

    public static String createIdFromNotification(String jti, String iss) {
        return jti + CryptoHelper.FIELDS_DELIMITER + iss;
    }

    public long getMaximumAllowedUsage() {
        return maximumAllowedUsage;
    }

    public Coupon.Type getType() {
        return type;
    }

    public long getUsagesCounter() {
        return usagesCounter;
    }

    public void setUsagesCounter(long usagesCounter) {
        this.usagesCounter = usagesCounter;
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
        if (useTimestamp==null){
            this.useTimestamp=new ArrayList<>();
        }
        this.useTimestamp.add(lastConsumptionTimestamp);
    }

    public CouponValidationStatus getStatus() {
        return status;
    }

    public void setStatus(CouponValidationStatus status) {
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

    public long getNumberOfUsedTimeFiltered(long begin, long end){
        if (useTimestamp != null){
            return useTimestamp
                    .stream()
                    .filter( x -> (x >= begin && x < end))
                    .count();
        }
        return 0;
    }
}
