package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateCredentials;
import eu.h2020.symbiote.security.services.CredentialsValidationService;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated to credentials validation.
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see CredentialsValidationService
 */
@RestController
@Api(value = "/docs/validateCredentials", description = "Exposes services used to validate coupons in given BTR")
public class ValidateCredentialsController implements IValidateCredentials {

    private Log log = LogFactory.getLog(ValidateCredentialsController.class);
    private CredentialsValidationService credentialsValidationService;

    @Autowired
    public ValidateCredentialsController(CredentialsValidationService credentialsValidationService,
                                         ValidationHelper validationHelper) {
        this.credentialsValidationService = credentialsValidationService;
    }

    @Override
    @ApiOperation(value = "Responds with validation status of processed Validation request", response = ValidationStatus.class)
    public ValidationStatus validate(
            @ApiParam(value = "Coupon to be validated", required = true)
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString) {
        try {
            // input sanity check
            JWTEngine.validateJWTString(couponString);

            // real validation
            return credentialsValidationService.validate(couponString);
        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }
    }
}
