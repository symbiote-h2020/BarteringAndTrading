package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.IssuedCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Helper for revoking coupons.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class RevocationHelper {
    private static final Logger log = LoggerFactory.getLogger(RevocationHelper.class);

    private final IssuedCouponsRepository issuedCouponsRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;


    @Autowired
    public RevocationHelper(IssuedCouponsRepository issuedCouponsRepository,
                            CertificationAuthorityHelper certificationAuthorityHelper) {
        this.issuedCouponsRepository = issuedCouponsRepository;
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
        if (!issuedCouponsRepository.exists(couponClaims.getJti())) {
            log.error("Coupon doesn't exist in issued coupons repository!");
            return false;
        }
        IssuedCoupon issuedCoupon = issuedCouponsRepository.findOne(couponClaims.getJti());
        issuedCoupon.setStatus(IssuedCoupon.Status.REVOKED);
        issuedCouponsRepository.save(issuedCoupon);
        log.debug("Coupon: %s was revoked succesfully", couponClaims.getJti());
        return true;

    }
}
