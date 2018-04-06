package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Exposes services allowing SymbIoTe actors (users) to acquire authorization tokens
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 * @author Daniele Caldarola (CNIT)
 * @author Pietro Tedeschi (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface IGetToken {
    /**
     * @param loginRequest JWS build in accordance to @{@link eu.h2020.symbiote.security.helpers.CryptoHelper#buildHomeTokenAcquisitionRequest(HomeCredentials)}
     *                     and http://www.smarteremc2.eu/colab/display/SYM/Home+Authorization+Token+acquisition+%28home+login%29+request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    @PostMapping(value = SecurityConstants.AAM_GET_HOME_TOKEN)
    ResponseEntity<String> getHomeToken(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME) String loginRequest);

}
