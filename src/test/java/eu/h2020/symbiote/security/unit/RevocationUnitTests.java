package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.AbstractBaTTestSuite;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.Credentials;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.services.RevocationService;
import eu.h2020.symbiote.security.services.helpers.TokenIssuer;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test suite for revocation (unit tests)
 *
 * @author Jakub Toczek (PSNC)
 */
@TestPropertySource("/core.properties")
public class RevocationUnitTests extends
        AbstractBaTTestSuite {

    @Autowired
    private RevocationService revocationService;
    @Autowired
    private TokenIssuer tokenIssuer;


    @Test
    public void revokeHomeTokenByAdminSuccess() throws
            JWTCreationException,
            MalformedJWTException {

        HomeCredentials homeCredentials = new HomeCredentials(null, username, clientId, null, userKeyPair.getPrivate());
        String loginRequest = CryptoHelper.buildHomeTokenAcquisitionRequest(homeCredentials);
        JWTClaims claims = JWTEngine.getClaimsFromToken(loginRequest);
        // acquiring valid token
        Token homeToken = tokenIssuer.getHomeToken(claims);

        RevocationRequest revocationRequest = new RevocationRequest();
        revocationRequest.setCredentials(new Credentials(AAMOwnerUsername, AAMOwnerPassword));
        revocationRequest.setCredentialType(RevocationRequest.CredentialType.ADMIN);
        revocationRequest.setHomeTokenString(homeToken.toString());

        // verify the user token is not yet revoked
        assertFalse(revokedTokensRepository.exists(homeToken.getClaims().getId()));
        // revocation
        revocationService.revoke(revocationRequest);

        // verify the user token is revoked
        assertTrue(revokedTokensRepository.exists(homeToken.getClaims().getId()));
    }

}