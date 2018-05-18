package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.BTMClient;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.repositories.StoredCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import eu.h2020.symbiote.security.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;

/**
 * Spring service used to provide token related functionality of the BAT.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("platform")
@Service
public class BarteralAccessManagementService {
    //TODO

    private static final String BTM_SUFFIX = "/btm";
    private static Log log = LogFactory.getLog(BarteralAccessManagementService.class);
    private final String btmCoreAddress;
    private final StoredCouponsRepository storedCouponsRepository;


    @Autowired
    public BarteralAccessManagementService(CouponIssuer couponIssuer,
                                           @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                                           CertificationAuthorityHelper certificationAuthorityHelper,
                                           ValidationHelper validationHelper,
                                           StoredCouponsRepository storedCouponsRepository) {
        this.btmCoreAddress = coreInterfaceAddress.endsWith("/aam") ? coreInterfaceAddress.substring(0, coreInterfaceAddress.length() - 4) + BTM_SUFFIX : coreInterfaceAddress + BTM_SUFFIX;
        this.storedCouponsRepository = storedCouponsRepository;
    }

    public boolean authorizeBarteralAccess(BarteralAccessRequest barteralAccessRequest) throws BTMException {
        HashSet<StoredCoupon> storedCouponHashSet = storedCouponsRepository.findAllByIssuerAndType(barteralAccessRequest.getClientPlatform(),
                barteralAccessRequest.getCouponType());
        BTMClient btmClient = new BTMClient(btmCoreAddress);
        for (StoredCoupon storedCoupon : storedCouponHashSet) {
            CouponValidity couponValidity = btmClient.isCouponValid(storedCoupon.getCouponString());
            if (couponValidity.getStatus().equals(CouponValidity.Status.INVALID)) {
                storedCouponsRepository.delete(storedCoupon.getId());
                continue;
            }
            btmClient.consumeCoupon(storedCoupon.getCouponString());
            return true;
            //check validity of coupon - if not - remove it.
            //if yes, consume it
        }
        //ask for new coupon
        //TODO
        return false;
    }

    public Coupon getCoupon(CouponRequest couponRequest) throws ValidationException {
        try {
            boolean isSecurityRequestValid = MutualAuthenticationHelper.isSecurityRequestVerified(couponRequest.getSecurityRequest());
            if (!isSecurityRequestValid) {
                throw new ValidationException(ValidationException.VALIDATION_ERROR_OCCURRED);
            }

        } catch (NoSuchAlgorithmException | MalformedJWTException | ValidationException | InvalidKeySpecException e) {
            log.error(e.getMessage());
            throw new ValidationException(ValidationException.VALIDATION_ERROR_OCCURRED);
        }

        //TODO
        return null;
    }
}
