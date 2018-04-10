package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Interfaces used to validate coupons in given BTR
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public interface IValidateCredentials {

    /**
     * @param coupon                                  that is to be validated
     * @return validation status
     */
    @PostMapping(SecurityConstants.BTR_VALIDATE_COUPON)
    ValidationStatus validate(
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String coupon);

}
