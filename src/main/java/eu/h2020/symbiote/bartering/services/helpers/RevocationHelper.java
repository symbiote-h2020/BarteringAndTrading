package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.bartering.repositories.RegisteredCouponRepository;
import eu.h2020.symbiote.bartering.repositories.entities.RegisteredCoupon;
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

    private final RegisteredCouponRepository registeredCouponRepository;


    @Autowired
    public RevocationHelper(RegisteredCouponRepository registeredCouponRepository) {
        this.registeredCouponRepository = registeredCouponRepository;
    }

    public boolean revokeCouponByAdmin(String couponString) throws
            ValidationException,
            MalformedJWTException {
        if (JWTEngine.validateJWTString(couponString) != ValidationStatus.VALID) {
            throw new ValidationException("Received coupon is not valid.");
        }
        JWTClaims couponClaims = JWTEngine.getClaimsFromJWT(couponString);
        if (!registeredCouponRepository.exists(RegisteredCoupon.createIdFromNotification(couponClaims.getJti(), couponClaims.getIss()))) {
            log.error("Coupon doesn't exist in issued coupons repository!");
            return false;
        }
        RegisteredCoupon registeredCoupon = registeredCouponRepository.findOne(RegisteredCoupon.createIdFromNotification(couponClaims.getJti(), couponClaims.getIss()));
        registeredCoupon.setStatus(CouponValidationStatus.REVOKED_COUPON);
        registeredCouponRepository.save(registeredCoupon);
        log.debug("Coupon: %s was revoked succesfully", couponClaims.getJti());
        return true;

    }
}