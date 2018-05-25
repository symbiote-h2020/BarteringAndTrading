package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.listeners.rest.interfaces.ICoreCouponManagement;
import eu.h2020.symbiote.security.services.CoreCouponManagementService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * Spring controller to handle HTTPS requests associated with coupon management in the CoreBTM.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
@Profile("core")
@RestController
public class CoreCouponManagementController implements ICoreCouponManagement {


    private CoreCouponManagementService coreCouponManagementService;
    private static Log log = LogFactory.getLog(CoreCouponManagementController.class);

    @Autowired
    public CoreCouponManagementController(CoreCouponManagementService coreCouponManagementService) {
        this.coreCouponManagementService = coreCouponManagementService;
    }

    @Override
    @ApiOperation(value = "Register coupon in the Core BTM.")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon was malformed"),
            @ApiResponse(code = 401, message = "Received coupon was not valid"),
            @ApiResponse(code = 500, message = "Internal server error occured (DB error, connection error)")})
    public ResponseEntity<String> registerCoupon(
            @RequestBody String couponString) {

        try {
            if (coreCouponManagementService.registerCoupon(couponString)) {
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (AAMException | MalformedJWTException | ValidationException | BTMException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        } catch (IOException | CertificateException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    @ApiOperation(value = "Consume coupon in the Core BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon didn't pass validation")})
    public ResponseEntity<String> consumeCoupon(@RequestBody String couponString) {
        try {
            CouponValidationStatus couponValidationStatus = coreCouponManagementService.consumeCoupon(couponString);
            switch (couponValidationStatus) {
                case VALID:
                    return new ResponseEntity<>(HttpStatus.OK);
                default:
                    return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
        } catch (MalformedJWTException e) {
            log.error("Received coupon was malformed");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

    }

    @Override
    @ApiOperation(value = "Coupon validation in Core BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon was malformed")})
    public ResponseEntity<CouponValidity> isCouponValid(@RequestBody String couponString) {
        try {
            CouponValidity couponValidity = coreCouponManagementService.isCouponValid(couponString);
            return new ResponseEntity<>(couponValidity, HttpStatus.OK);

        } catch (MalformedJWTException e) {
            log.error("Received coupon was malformed");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

    }

    @Override
    @ApiOperation(value = "Cleanup all consumed coupons before provided timestamp")
    public ResponseEntity<Integer> cleanupConsumedCoupons(@RequestBody long timestamp) {
        int removed = coreCouponManagementService.cleanupConsumedCoupons(timestamp);
        return new ResponseEntity<>(removed, HttpStatus.OK);
    }


}
