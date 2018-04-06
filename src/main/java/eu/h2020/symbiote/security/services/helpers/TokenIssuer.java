package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Used to issue tokens.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class TokenIssuer {

    private static Log log = LogFactory.getLog(TokenIssuer.class);
    private static SecureRandom random = new SecureRandom();
    // AAM configuration
    private final String deploymentId;
    private final IssuingAuthorityType deploymentType;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    @Value("${bat.deployment.token.validityMillis}")
    private Long tokenValidity;

    @Autowired
    public TokenIssuer(CertificationAuthorityHelper certificationAuthorityHelper) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
    }

    public static String buildAuthorizationToken(String subject,
                                                 Map<String, String> attributes,
                                                 //  byte[] subjectPublicKey,
                                                 Token.Type tokenType,
                                                 Long tokenValidity,
                                                 String issuer,
                                                 PublicKey issuerPublicKey,
                                                 PrivateKey issuerPrivateKey) {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        // Insert AAM Public Key
        claimsMap.put("ipk", Base64.getEncoder().encodeToString(issuerPublicKey.getEncoded()));

        //TODO?
        //Insert issuee Public Key
        // claimsMap.put("spk", Base64.getEncoder().encodeToString(subjectPublicKey));

        //Add symbIoTe related attributes to token
        if (attributes != null && !attributes.isEmpty()) {
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                claimsMap.put(entry.getKey(), entry.getValue());
            }
        }

        //Insert token type
        claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, tokenType);

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setClaims(claimsMap);
        jwtBuilder.setId(jti);
        jwtBuilder.setIssuer(issuer);
        jwtBuilder.setSubject(subject);
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.setExpiration(new Date(System.currentTimeMillis() + tokenValidity));
        jwtBuilder.signWith(SignatureAlgorithm.ES256, issuerPrivateKey);

        return jwtBuilder.compact();
    }


    public Token getHomeToken(JWTClaims claims)
            throws JWTCreationException {
        try {
            Map<String, String> attributes = new HashMap<>();
            if (deploymentType.equals(IssuingAuthorityType.NULL))
                throw new JWTCreationException(JWTCreationException.MISCONFIGURED_AAM_DEPLOYMENT_TYPE);
            //adding local user's attributes
            String subject = claims.getSub();

            return new Token(buildAuthorizationToken(
                    subject,
                    attributes,
                    //TODO issuerPublicKey.getEncoded(),
                    Token.Type.HOME,
                    tokenValidity,
                    deploymentId,
                    certificationAuthorityHelper.getAAMPublicKey(),
                    certificationAuthorityHelper.getAAMPrivateKey()
            ));
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

}
