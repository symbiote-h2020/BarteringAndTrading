package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.StoredCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Helper for revoking coupons.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Profile("platform")
@Component
public class RevocationHelper {
    private static final Logger log = LoggerFactory.getLogger(RevocationHelper.class);

    private final StoredCouponsRepository storedCouponsRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;


    @Autowired
    public RevocationHelper(StoredCouponsRepository storedCouponsRepository,
                            CertificationAuthorityHelper certificationAuthorityHelper) {
        this.storedCouponsRepository = storedCouponsRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
    }


    public boolean revokeCouponByAdmin(String couponString) throws
            ValidationException,
            MalformedJWTException {
        if (JWTEngine.validateJWTString(couponString) != ValidationStatus.VALID) {
            throw new ValidationException(ValidationException.INVALID_TOKEN);
        }
        JWTClaims couponClaims = JWTEngine.getClaimsFromJWT(couponString);
        if (!certificationAuthorityHelper.getBTMInstanceIdentifier().equals(couponClaims.getIss())) {
            log.error("Coupon was not issued by this BTM. The issuer is: " + couponClaims.getIss());
            return false;
        }
        if (!couponClaims.getIpk().equals(Base64.getEncoder().encodeToString(certificationAuthorityHelper.getBTMPublicKey().getEncoded()))) {
            log.error("Public key from coupon differs from owned by BTM.");
            return false;
        }
        if (!storedCouponsRepository.exists(couponClaims.getJti())) {
            log.error("Coupon doesn't exist in issued coupons repository!");
            return false;
        }
        StoredCoupon storedCoupon = storedCouponsRepository.findOne(couponClaims.getJti());
        storedCoupon.setStatus(StoredCoupon.Status.REVOKED);
        storedCouponsRepository.save(storedCoupon);
        log.debug("Coupon: %s was revoked succesfully", couponClaims.getJti());
        return true;

    }
}
