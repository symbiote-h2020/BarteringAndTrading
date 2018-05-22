package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IBarteralAccessManagement;
import eu.h2020.symbiote.security.services.BarteralAccessManagementService;
import io.swagger.annotations.Api;
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


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with acquiring barteral access and getting coupons
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see BarteralAccessManagementService
 */
@Profile("platform")
@RestController
@Api(value = "/docs/barteralAccessManagement", description = "Exposes services responsible for getting access to the bartered resources")
public class BarteralAccessManagementController implements IBarteralAccessManagement {

    private static Log log = LogFactory.getLog(BarteralAccessManagementController.class);
    private BarteralAccessManagementService barteralAccessManagementService;

    @Autowired
    public BarteralAccessManagementController(BarteralAccessManagementService barteralAccessManagementService) {
        this.barteralAccessManagementService = barteralAccessManagementService;
    }

    @Override
    @ApiOperation(value = "Request coupon from foreign BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Error validating couponRequest occured"),
            @ApiResponse(code = 500, message = "Internal server error occured")})
    public ResponseEntity<String> getCoupon(@RequestBody CouponRequest couponRequest) {
        try {
            return new ResponseEntity<>(barteralAccessManagementService.getCoupon(couponRequest), HttpStatus.OK);
        } catch (ValidationException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>("Wrong couponRequest", HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException | BTMException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    //TODO
    @Override
    @ApiOperation(value = "Request for barteral access")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Access granted."),
            @ApiResponse(code = 400, message = "TODO"),
            @ApiResponse(code = 500, message = "TODO")})
    public ResponseEntity<String> authorizeBarteralAccess(@RequestBody BarteralAccessRequest barteralAccessRequest) {
        try {
            //checking request
            if (barteralAccessRequest.getClientPlatform() == null ||
                    barteralAccessRequest.getClientPlatform().isEmpty() ||
                    barteralAccessRequest.getResourceId() == null ||
                    barteralAccessRequest.getResourceId().isEmpty() ||
                    barteralAccessRequest.getCouponType() == null) {
                throw new InvalidArgumentsException("BarteralAccessRequest doesn't contain all required fields.");
            }
            if (barteralAccessManagementService.authorizeBarteralAccess(barteralAccessRequest)) {
                return new ResponseEntity<>(HttpStatus.OK);
            }
            //TODO
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        } catch (InvalidArgumentsException | BTMException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(e.getErrorMessage(), HttpStatus.BAD_REQUEST);
        }
    }
}