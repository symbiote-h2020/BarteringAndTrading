package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ConsumedCouponsRepository;
import eu.h2020.symbiote.security.repositories.ValidCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.ValidCoupon;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;

/**
 * Spring service used to provide token related functionality of the BAT.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Service
public class ManageCouponService {

    private static Log log = LogFactory.getLog(ManageCouponService.class);
    private final CouponIssuer couponIssuer;
    private final String coreInterfaceAddress;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final ValidationHelper validationHelper;

    private final ValidCouponsRepository validCouponsRepository;
    private final ConsumedCouponsRepository consumedCouponsRepository;


    @Autowired
    public ManageCouponService(CouponIssuer couponIssuer,
                               @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                               CertificationAuthorityHelper certificationAuthorityHelper,
                               ValidationHelper validationHelper,
                               ValidCouponsRepository validCouponsRepository,
                               ConsumedCouponsRepository consumedCouponsRepository) {
        this.couponIssuer = couponIssuer;
        this.coreInterfaceAddress = coreInterfaceAddress;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.validationHelper = validationHelper;
        this.validCouponsRepository = validCouponsRepository;
        this.consumedCouponsRepository = consumedCouponsRepository;
    }

    public Coupon getDiscreteCoupon(String loginRequest) throws
            MalformedJWTException,
            InvalidArgumentsException,
            JWTCreationException,
            ValidationException,
            IOException,
            CertificateException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromJWT(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new InvalidArgumentsException();
        }

        String componentCertificate;
        AAMClient aamClient = new AAMClient(coreInterfaceAddress);
        try {
            componentCertificate = aamClient.getComponentCertificate(claims.getSub(), claims.getIss());
        } catch (AAMException e) {
            log.error(e);
            throw new ValidationException("Core AAM is not available. Please, check your connection.");
        }
        PublicKey componentPublicKey = CryptoHelper.convertPEMToX509(componentCertificate).getPublicKey();
        if (ValidationStatus.VALID != JWTEngine.validateJWTString(loginRequest, componentPublicKey)) {
            String message = String.format("Certificate public key of %s mismatch with this acquired from %s", claims.getSub(), claims.getIss());
            log.error(message);
            throw new ValidationException(message);
        }
        return couponIssuer.getDiscreteCoupon();
    }

    public boolean consumeCoupon(String couponString) throws
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException {
        Coupon coupon = new Coupon(couponString);
        // validate coupon
        if (!validationHelper.validate(couponString).equals(CouponValidationStatus.VALID)) {
            throw new InvalidArgumentsException("Coupon is not valid.");
        }
        ValidCoupon validCoupon = validCouponsRepository.findOne(coupon.getId());
        if (validCoupon.getCoupon().getType().equals(Coupon.Type.DISCRETE)) {
            Long validity = validCoupon.getValidity();
            if (validity <= 1) {
                consumedCouponsRepository.save(validCoupon.getCoupon());
                validCouponsRepository.delete(coupon.getId());
            } else {
                validCoupon.setValidity(validity - 1);
            }
            return true;
        }
        //TODO add PERIODIC coupon
        return false;

    }
}
