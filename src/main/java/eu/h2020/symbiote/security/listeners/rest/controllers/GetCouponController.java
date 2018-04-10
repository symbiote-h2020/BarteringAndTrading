package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.SecurityException;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IGetCoupon;
import eu.h2020.symbiote.security.services.GetCouponService;
import io.swagger.annotations.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with acquiring coupons.
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see GetCouponService
 */
@RestController
@Api(value = "/docs/getCoupons", description = "Exposes services responsible for providing Coupons")
public class GetCouponController implements IGetCoupon {

    private final GetCouponService getCouponService;
    private Log log = LogFactory.getLog(GetCouponController.class);

    @Autowired
    public GetCouponController(GetCouponService getCouponService) {
        this.getCouponService = getCouponService;
    }

    //L1 Diagrams - getDiscreteCoupon()
    @ApiOperation(value = "Issues a Discrete Coupon")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Received coupon was malformed"),
            @ApiResponse(code = 401, message = "Incorrect Credentials were provided"),
            @ApiResponse(code = 500, message = "Server failed to create Coupon")})
    public ResponseEntity<String> getDiscreteCoupon(
            @RequestHeader(SecurityConstants.COUPON_HEADER_NAME)
            @ApiParam(value = "JWS built in accordance to Symbiote Security Cryptohelper", required = true) String loginRequest) {
        try {
            Coupon coupon = getCouponService.getDiscreteCoupon(loginRequest);
            HttpHeaders headers = new HttpHeaders();
            headers.add(SecurityConstants.COUPON_HEADER_NAME, coupon.getCoupon());
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (SecurityException e) {
            log.error(e);
            return new ResponseEntity<>(e.getErrorMessage(), e.getStatusCode());
        } catch (Exception e) {
            log.error(e);
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }
}