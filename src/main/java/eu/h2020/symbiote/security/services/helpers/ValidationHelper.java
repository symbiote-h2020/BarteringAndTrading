package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.ConsumedCouponsRepository;
import eu.h2020.symbiote.security.repositories.RevokedCouponsRepository;
import eu.h2020.symbiote.security.repositories.ValidCouponsRepository;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Used to validate given credentials against data in the AAMs
 * <p>
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class ValidationHelper {

    private static Log log = LogFactory.getLog(ValidationHelper.class);

    // AAM configuration
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final RevokedCouponsRepository revokedCouponsRepository;
    private final ConsumedCouponsRepository consumedCouponsRepository;
    private final ValidCouponsRepository validCouponsRepository;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedCouponsRepository revokedCouponsRepository,
                            ConsumedCouponsRepository consumedCouponsRepository,
                            ValidCouponsRepository validCouponsRepository) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.revokedCouponsRepository = revokedCouponsRepository;
        this.consumedCouponsRepository = consumedCouponsRepository;
        this.validCouponsRepository = validCouponsRepository;
    }

    public CouponValidationStatus validate(String coupon) throws MalformedJWTException {

        //TODO @JT it's only draft, change it
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateJWTString(coupon);
            if (validationStatus != ValidationStatus.VALID) {
                //TODO @JT
                throw new MalformedJWTException();
            }
            Claims claims = new Coupon(coupon).getClaims();
            if (claims.getIssuer() == null ||
                    !claims.getIssuer().equals(certificationAuthorityHelper.getBTMInstanceIdentifier())) {
                log.error("Issuer of this coupon is unknown.");
                throw new MalformedJWTException();
            }
            // check revoked JTI
            if (revokedCouponsRepository.exists(claims.getId())) {
                return CouponValidationStatus.REVOKED_COUPON;
            }
            // check consumed coupons
            if (consumedCouponsRepository.exists(claims.getId())) {
                return CouponValidationStatus.CONSUMED_COUPON;
            }
            // check in valid repo
            if (!validCouponsRepository.exists(claims.getId())) {
                return CouponValidationStatus.UNKNOWN;
            }
        } catch (ValidationException e) {
            log.error(e);
            return CouponValidationStatus.UNKNOWN;
        }
        return CouponValidationStatus.VALID;

    }
}
