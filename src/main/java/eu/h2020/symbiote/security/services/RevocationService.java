package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.communication.payloads.RevocationResponse;
import eu.h2020.symbiote.security.services.helpers.RevocationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Spring service used to revoke tokens and certificates.
 * * @author Jakub Toczek (PSNC)
 */

@Service
public class RevocationService {
    private static Log log = LogFactory.getLog(RevocationService.class);
    private final RevocationHelper revocationHelper;
    private final PasswordEncoder passwordEncoder;
    @Value("${btm.deployment.owner.username}")
    private String BTMOwnerUsername;
    @Value("${btm.deployment.owner.password}")
    private String BTMOwnerPassword;

    @Autowired
    public RevocationService(RevocationHelper revocationHelper, PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.revocationHelper = revocationHelper;
    }

    public RevocationResponse revoke(RevocationRequest revocationRequest) {
        try {
            if (revocationRequest.getCredentialType() == RevocationRequest.CredentialType.ADMIN) {
                return adminRevoke(revocationRequest);
            }
        } catch (IllegalArgumentException | SecurityException e) {
            log.error(e.getMessage());
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        } catch (ValidationException | MalformedJWTException e) {
            log.error(e.getMessage());
            return new RevocationResponse(false, e.getStatusCode());
        }

        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);


    }

    private RevocationResponse adminRevoke(RevocationRequest revocationRequest) throws
            ValidationException,
            MalformedJWTException {
        if (!revocationRequest.getCredentials().getUsername().equals(BTMOwnerUsername)
                || !passwordEncoder.matches(revocationRequest.getCredentials().getPassword(), passwordEncoder.encode(BTMOwnerPassword))) {
            log.error(WrongCredentialsException.AUTHENTICATION_OF_USER_FAILED);
            return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
        }
        if (!revocationRequest.getCouponString().isEmpty()) {
            return new RevocationResponse(this.revocationHelper.revokeCouponByAdmin(revocationRequest.getCouponString()), HttpStatus.OK);
        }
        log.error(InvalidArgumentsException.REQUEST_IS_INCORRECTLY_BUILT);
        return new RevocationResponse(false, HttpStatus.BAD_REQUEST);
    }

}
