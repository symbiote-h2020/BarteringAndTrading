package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.listeners.rest.interfaces.IRevokeCredentials;
import eu.h2020.symbiote.security.services.RevocationService;
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
 * @see RevocationService
 */
@Profile("platform")
@Api(value = "/docs/revokeCoupons", description = "Exposes services allowing SymbIoTe actors to revoke their coupons")
@RestController
public class RevocationController implements IRevokeCredentials {
    private RevocationService revocationService;

    @Autowired
    public RevocationController(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Override
    @ApiOperation(value = "Allows users to revoke their coupons")
    @ApiResponses({
            @ApiResponse(code = 400, message = "Request contains invalid arguments"),
            @ApiResponse(code = 401, message = "Incorrect credentials were provided")})
    public ResponseEntity<String> revoke(
            @RequestBody
            @ApiParam(name = "Revocation Request", value = "Depending on it's fields, coupons can be revoked", required = true)
                    RevocationRequest revocationRequest) {
        RevocationResponse revocationResponse = revocationService.revoke(revocationRequest);
        return ResponseEntity.status(revocationResponse.getStatus()).body(String.valueOf(revocationResponse.isRevoked()));
    }
}
