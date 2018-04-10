package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.RevokedCouponsRepository;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

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
    private final String deploymentId;
    private final IssuingAuthorityType deploymentType;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final RevokedCouponsRepository revokedCouponsRepository;

    // usable
    private final RestTemplate restTemplate = new RestTemplate();
    private final String coreInterfaceAddress;
    @Value("${btr.deployment.coupon.validity}")
    private Long tokenValidity;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedCouponsRepository revokedCouponsRepository,
                            @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.revokedCouponsRepository = revokedCouponsRepository;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public ValidationStatus validate(String coupon) {

        //TODO @JT it's only draft, change it
        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateJWTString(coupon);
            if (validationStatus != ValidationStatus.VALID) {
                return validationStatus;
            }
            Claims claims = new Coupon(coupon).getClaims();
            // check revoked JTI
            if (revokedCouponsRepository.exists(claims.getId())) {
                return ValidationStatus.REVOKED_TOKEN;
            }

        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
        return ValidationStatus.VALID;
    }
}
