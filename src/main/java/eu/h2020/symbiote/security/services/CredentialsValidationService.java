package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

/**
 * Spring service used to provide validation functionality of the AAM.
 *
 * @author Piotr Kicki (PSNC)
 */
@Profile("service")
@Service
public class CredentialsValidationService {
    private final ValidationHelper validationHelper;

    @Autowired
    public CredentialsValidationService(ValidationHelper validationHelper) {
        this.validationHelper = validationHelper;
    }

    public CouponValidationStatus validate(String couponString) throws MalformedJWTException {
        return validationHelper.validate(couponString);
    }
}
