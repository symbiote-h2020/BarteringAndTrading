package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Exposes services allowing SymbIoTe components to acquire coupons
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public interface IGetCoupon {
    /**
     * //TODO @JT change documentation
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return Coupon used to access resources offered in SymbIoTe
     */
    @PostMapping(value = SecurityConstants.BTR_GET_DISCRETE_COUPON)
    ResponseEntity<String> getDiscreteCoupon(@RequestHeader(SecurityConstants.COUPON_HEADER_NAME) String loginRequest);

}
