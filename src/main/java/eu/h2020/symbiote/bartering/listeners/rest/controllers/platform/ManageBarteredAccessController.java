package eu.h2020.symbiote.bartering.listeners.rest.controllers.platform;

import eu.h2020.symbiote.bartering.listeners.rest.interfaces.platform.IManageBarteredAccess;
import eu.h2020.symbiote.bartering.services.BarteredAccessManagementService;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
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
 * Spring controller to handle HTTP requests related to the RESTful web services associated with acquiring bartered access and getting coupons
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 * @see BarteredAccessManagementService
 */
@Profile("platform")
@RestController
@Api(value = "/docs/barteredAccessManagement", description = "Exposes services responsible for getting access to the bartered resources")
public class ManageBarteredAccessController implements IManageBarteredAccess {

    private static Log log = LogFactory.getLog(ManageBarteredAccessController.class);
    private BarteredAccessManagementService barteredAccessManagementService;

    @Autowired
    public ManageBarteredAccessController(BarteredAccessManagementService barteredAccessManagementService) {
        this.barteredAccessManagementService = barteredAccessManagementService;
    }

    @Override
    @ApiOperation(value = "Request coupon from remote federated BTM")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Error validating couponRequest occurred"),
            @ApiResponse(code = 500, message = "Internal server error occurred")})
    public ResponseEntity<String> getCoupon(@RequestBody CouponRequest couponRequest) {
        try {
            return new ResponseEntity<>(barteredAccessManagementService.getCoupon(couponRequest), HttpStatus.OK);
        } catch (ValidationException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>("Wrong couponRequest", HttpStatus.BAD_REQUEST);
        } catch (JWTCreationException | BTMException | WrongCredentialsException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    @ApiOperation(value = "Request for bartered access")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Access granted."),
            @ApiResponse(code = 400, message = "Access was not granted due to bad request"),
            @ApiResponse(code = 500, message = "Internal server error.")})
    public ResponseEntity<String> authorizeBarteredAccess(@RequestBody BarteredAccessRequest barteredAccessRequest) {
        try {
            //checking request
            if (barteredAccessRequest.getClientPlatform() == null ||
                    barteredAccessRequest.getClientPlatform().isEmpty() ||
                    barteredAccessRequest.getResourceId() == null ||
                    barteredAccessRequest.getResourceId().isEmpty() ||
                    barteredAccessRequest.getCouponType() == null) {
                throw new InvalidArgumentsException("BarteredAccessRequest doesn't contain all required fields.");
            }
            if (barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest)) {
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        } catch (InvalidArgumentsException | ValidationException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(e.getErrorMessage(), HttpStatus.BAD_REQUEST);
        } catch (SecurityHandlerException | BTMException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(e.getErrorMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (WrongCredentialsException e) {
            log.error(e.getMessage());
            return new ResponseEntity<>(e.getErrorMessage(), HttpStatus.UNAUTHORIZED);
        }
    }
}