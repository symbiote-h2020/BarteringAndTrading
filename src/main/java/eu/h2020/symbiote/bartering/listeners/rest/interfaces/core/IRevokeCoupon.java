package eu.h2020.symbiote.bartering.listeners.rest.interfaces.core;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Exposes services allowing SymbIoTe actors (users) to revoke their coupons
 *
 * @author Jakub Toczek (PSNC)
 */
public interface IRevokeCoupon {
    /**
     * Exposes a service that allows users to revoke their coupons.
     *
     * @param revocationRequest required to revoke. Depending on it's fields, coupons can be revoked.
     * @return ResponseEntity<String> where as header HTTP status is sent and in body true/false depending on revocation status
     */
    @PostMapping(value = SecurityConstants.BTM_REVOKE_COUPON, consumes = "application/json")
    ResponseEntity<String> revoke(@RequestBody RevocationRequest revocationRequest);
}
