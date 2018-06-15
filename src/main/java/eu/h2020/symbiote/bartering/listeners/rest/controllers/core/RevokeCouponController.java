package eu.h2020.symbiote.bartering.listeners.rest.controllers.core;

import eu.h2020.symbiote.bartering.listeners.rest.interfaces.core.IRevokeCoupon;
import eu.h2020.symbiote.bartering.services.CouponRevocationService;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring controller to handle HTTPS requests related to the RESTful web services associated with revoking coupons.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 * @see CouponRevocationService
 */
@Profile("core")
@Api(value = "/docs/revokeCoupons", description = "Exposes services allowing SymbIoTe Platforms to revoke their coupons")
@RestController
public class RevokeCouponController implements IRevokeCoupon {
    private CouponRevocationService couponRevocationService;

    @Autowired
    public RevokeCouponController(CouponRevocationService couponRevocationService) {
        this.couponRevocationService = couponRevocationService;
    }

    @Override
    @ApiOperation(value = "Allows Platforms to revoke their coupons")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Request contains invalid arguments"),
            @ApiResponse(code = 401, message = "Incorrect credentials were provided")})
    public ResponseEntity<String> revoke(
            @RequestBody
            @ApiParam(name = "Revocation Request", value = "Depending on it's fields, coupons can be revoked", required = true)
                    RevocationRequest revocationRequest) {
        RevocationResponse revocationResponse = couponRevocationService.revoke(revocationRequest);
        return ResponseEntity.status(revocationResponse.getStatus()).body(String.valueOf(revocationResponse.isRevoked()));
    }
}
