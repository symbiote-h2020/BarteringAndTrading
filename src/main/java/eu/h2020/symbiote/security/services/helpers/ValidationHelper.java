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
import eu.h2020.symbiote.security.repositories.StoredCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.CertificateException;

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
@Profile("platform")
@Component
public class ValidationHelper {

    private static Log log = LogFactory.getLog(ValidationHelper.class);

    // AAM configuration
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final StoredCouponsRepository storedCouponsRepository;
    private final AAMClient aamClient;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            StoredCouponsRepository storedCouponsRepository,
                            @Value("${symbIoTe.localaam.url}") String localAAMAddress) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.storedCouponsRepository = storedCouponsRepository;
        this.aamClient = new AAMClient(localAAMAddress);
    }

    public CouponValidationStatus validate(String coupon) throws MalformedJWTException {

        try {
            Claims claims = new Coupon(coupon).getClaims();
            ValidationStatus validationStatus = validateJWT(coupon, claims);
            if (validationStatus != ValidationStatus.VALID) {
                throw new MalformedJWTException();
            }
            // check if coupon in db
            if (!storedCouponsRepository.exists(claims.getId())) {
                return CouponValidationStatus.COUPON_NOT_IN_DB;
            }
            StoredCoupon storedCoupon = storedCouponsRepository.findOne(claims.getId());
            //check if coupons are the same
            if (!storedCoupon.getCouponString().equals(coupon)) {
                return CouponValidationStatus.DB_MISMATCH;
            }
            // check if coupon is revoked
            if (storedCoupon.getStatus().equals(StoredCoupon.Status.REVOKED)) {
                return CouponValidationStatus.REVOKED_COUPON;
            }

            // check if coupon is consumed
            if (storedCoupon.getStatus().equals(StoredCoupon.Status.CONSUMED)) {
                return CouponValidationStatus.CONSUMED_COUPON;
            }
            // check in valid repo
            if (!storedCoupon.getStatus().equals(StoredCoupon.Status.VALID)
                    || storedCoupon.getValidity() < 1) {
                return CouponValidationStatus.UNKNOWN;
            }
        } catch (ValidationException | AAMException | IOException | CertificateException e) {
            log.error(e);
            return CouponValidationStatus.UNKNOWN;
        }
        return CouponValidationStatus.VALID;

    }

    public ValidationStatus validateJWT(String coupon, Claims claims) throws MalformedJWTException, IOException, AAMException, ValidationException, CertificateException {
        if (claims.getIssuer() == null) {
            log.error("Issuer of this coupon is unknown.");
            throw new MalformedJWTException();
        }
        String issuerCertificate;
        issuerCertificate = (claims.getIssuer().equals(certificationAuthorityHelper.getBTMInstanceIdentifier()) ?
                certificationAuthorityHelper.getBTMCert() :
                aamClient.getComponentCertificate("btm", claims.getIssuer()));
        //basic validation (signature and exp)
        return JWTEngine.validateJWTString(coupon, CryptoHelper.convertPEMToX509(issuerCertificate).getPublicKey());
    }
}
