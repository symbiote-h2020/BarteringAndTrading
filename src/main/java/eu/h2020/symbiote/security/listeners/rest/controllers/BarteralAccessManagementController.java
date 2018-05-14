package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.communication.payloads.BarteralAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IBarteralAccessManagement;
import eu.h2020.symbiote.security.services.ManageCouponService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
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
 * @see ManageCouponService
 */
@Profile("platform")
@RestController
@Api(value = "/docs/barteralAccessManagement", description = "Exposes services responsible for getting access to the bartered resources")
public class BarteralAccessManagementController implements IBarteralAccessManagement {

    //TODO
    @Override
    @ApiOperation(value = "Request coupon from foreign BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "TODO"),
            @ApiResponse(code = 500, message = "TODO")})
    public ResponseEntity<String> getCoupon(@RequestBody CouponRequest couponRequest) {
        return new ResponseEntity<>(new Coupon().getCoupon(), HttpStatus.OK);
    }

    //TODO
    @Override
    @ApiOperation(value = "Request for barteral access")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Access granted."),
            @ApiResponse(code = 400, message = "TODO"),
            @ApiResponse(code = 500, message = "TODO")})
    public ResponseEntity<String> authorizeBarteralAccess(@RequestBody BarteralAccessRequest barteralAccessRequest) {
        return new ResponseEntity<>(HttpStatus.OK);
    }
}