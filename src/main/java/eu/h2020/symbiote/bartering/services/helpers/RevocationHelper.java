package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.bartering.repositories.GlobalCouponsRegistry;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Helper for revoking coupons.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Profile("core")
@Component
public class RevocationHelper {
    private static final Logger log = LoggerFactory.getLogger(RevocationHelper.class);

    private final GlobalCouponsRegistry globalCouponsRegistry;


    @Autowired
    public RevocationHelper(GlobalCouponsRegistry globalCouponsRegistry) {
        this.globalCouponsRegistry = globalCouponsRegistry;
    }

    /**
     * TODO do we really need it? Who can revoke coupons... admin? Core Admin? or the Platform Owner can, should he be able to?
     */
    public boolean revokeCouponByAdmin(String coupon) throws
            ValidationException,
            MalformedJWTException {
        if (JWTEngine.validateTokenString(coupon) != ValidationStatus.VALID) {
            throw new ValidationException("Received coupon is not valid.");
        }
        JWTClaims couponClaims = JWTEngine.getClaimsFromToken(coupon);
        if (!globalCouponsRegistry.exists(AccountingCoupon.createIdFromNotification(couponClaims.getJti(), couponClaims.getIss()))) {
            log.error("CouponEntity doesn't exist in issued coupons repository!");
            return false;
        }
        AccountingCoupon accountingCoupon = globalCouponsRegistry.findOne(AccountingCoupon.createIdFromNotification(couponClaims.getJti(), couponClaims.getIss()));
        accountingCoupon.setStatus(CouponValidationStatus.REVOKED_COUPON);
        globalCouponsRegistry.save(accountingCoupon);
        log.debug("CouponEntity: %s was revoked succesfully", couponClaims.getJti());
        return true;

    }
}
