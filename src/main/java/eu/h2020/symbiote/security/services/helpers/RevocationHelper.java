package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.RevokedCouponsRepository;
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

    private final RevokedCouponsRepository revokedCouponsRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;


    @Autowired
    public RevocationHelper(RevokedCouponsRepository revokedCouponsRepository,
                            CertificationAuthorityHelper certificationAuthorityHelper) {
        this.revokedCouponsRepository = revokedCouponsRepository;
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
            return false;
        }
        if (!couponClaims.getIpk().equals(Base64.getEncoder().encodeToString(certificationAuthorityHelper.getAAMPublicKey().getEncoded()))) {
            return false;
        }
        revokedCouponsRepository.save(new Coupon(couponString));
        log.debug("Coupon: %s was removed succesfully", couponClaims.getJti());
        return true;

    }
}
