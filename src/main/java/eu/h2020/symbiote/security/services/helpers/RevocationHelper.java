package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Helper for revoking credentials.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class RevocationHelper {
    private static final Logger log = LoggerFactory.getLogger(RevocationHelper.class);

    private final RevokedTokensRepository revokedTokensRepository;
    private final CertificationAuthorityHelper certificationAuthorityHelper;


    @Autowired
    public RevocationHelper(RevokedTokensRepository revokedTokensRepository,
                            CertificationAuthorityHelper certificationAuthorityHelper) {
        this.revokedTokensRepository = revokedTokensRepository;
        this.certificationAuthorityHelper = certificationAuthorityHelper;
    }


    public boolean revokeHomeTokenByAdmin(String token) throws
            ValidationException,
            MalformedJWTException {
        if (JWTEngine.validateTokenString(token) != ValidationStatus.VALID) {
            throw new ValidationException(ValidationException.INVALID_TOKEN);
        }
        JWTClaims tokenClaims = JWTEngine.getClaimsFromToken(token);
        if (!certificationAuthorityHelper.getAAMInstanceIdentifier().equals(tokenClaims.getIss())) {
            return false;
        }
        if (!tokenClaims.getIpk().equals(Base64.getEncoder().encodeToString(certificationAuthorityHelper.getAAMPublicKey().getEncoded()))) {
            return false;
        }
        revokedTokensRepository.save(new Token(token));
        log.debug("Token: %s was removed succesfully", token);
        return true;

    }
}
