package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IValidateCredentials;
import eu.h2020.symbiote.security.services.ValidationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with credentials validation.
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see ValidationService
 */
@Profile("platform")
@RestController
@Api(value = "/docs/validateCoupons", description = "Exposes services used to validate coupons in given BTM")
public class ValidateCouponsController implements IValidateCredentials {

    private Log log = LogFactory.getLog(ValidateCouponsController.class);
    private ValidationService validationService;

    @Autowired
    public ValidateCouponsController(ValidationService validationService) {
        this.validationService = validationService;
    }

    @Override
    @ApiOperation(value = "Responds with validation status of processed validation request", response = CouponValidationStatus.class)
    public CouponValidationStatus validate(
            @ApiParam(value = "Coupon to be valida ted", required = true)
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String couponString) {
        try {
            // input sanity check
            JWTEngine.validateJWTString(couponString);

            // real validation
            return validationService.validate(couponString);
        } catch (ValidationException | MalformedJWTException e) {
            log.error(e);
            return CouponValidationStatus.UNKNOWN;
        }
    }
}
