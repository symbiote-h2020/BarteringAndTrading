package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.IssuedCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;

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
@Profile("service")
@Component
public class ValidationHelper {

    private static Log log = LogFactory.getLog(ValidationHelper.class);

    // AAM configuration
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final IssuedCouponsRepository issuedCouponsRepository;
    private final AAMClient aamClient;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            IssuedCouponsRepository issuedCouponsRepository,
                            @Value("${symbIoTe.localaam.url}") String localAAMAddress) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.issuedCouponsRepository = issuedCouponsRepository;
        this.aamClient = new AAMClient(localAAMAddress);
    }

    public CouponValidationStatus validate(String coupon) throws MalformedJWTException {

        //TODO @JT it's only draft, change it
        try {

            Claims claims = new Coupon(coupon).getClaims();
            if (claims.getIssuer() == null) {
                log.error("Issuer of this coupon is unknown.");
                throw new MalformedJWTException();
            }
            String issuerCertificate;
            issuerCertificate = (claims.getIssuer().equals(certificationAuthorityHelper.getBTMInstanceIdentifier()) ?
                    certificationAuthorityHelper.getBTMCert() :
                    aamClient.getComponentCertificate("btm", claims.getIssuer()));
            //basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateJWTString(coupon, CryptoHelper.convertPEMToPublicKey(issuerCertificate));
            if (validationStatus != ValidationStatus.VALID) {
                throw new MalformedJWTException();
            }
            // check if coupon in db
            if (!issuedCouponsRepository.exists(claims.getId())) {
                return CouponValidationStatus.COUPON_NOT_IN_DB;
            }
            IssuedCoupon issuedCoupon = issuedCouponsRepository.findOne(claims.getId());
            //check if coupons are the same
            if (!issuedCoupon.getCouponString().equals(coupon)) {
                return CouponValidationStatus.DB_MISMATCH;
            }
            // check if coupon is revoked
            if (issuedCoupon.getStatus().equals(IssuedCoupon.Status.REVOKED)) {
                return CouponValidationStatus.REVOKED_COUPON;
            }

            // check if coupon is consumed
            if (issuedCoupon.getStatus().equals(IssuedCoupon.Status.CONSUMED)) {
                return CouponValidationStatus.CONSUMED_COUPON;
            }
            // check in valid repo
            if (!issuedCoupon.getStatus().equals(IssuedCoupon.Status.VALID)
                    || issuedCoupon.getValidity() < 1) {
                return CouponValidationStatus.UNKNOWN;
            }
        } catch (ValidationException | AAMException | IOException e) {
            log.error(e);
            return CouponValidationStatus.UNKNOWN;
        }
        return CouponValidationStatus.VALID;

    }
}
