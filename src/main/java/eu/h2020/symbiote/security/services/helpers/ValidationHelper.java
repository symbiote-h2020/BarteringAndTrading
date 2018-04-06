package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.RevokedTokensRepository;
import eu.h2020.symbiote.security.services.CacheService;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Used to validate given credentials against data in the AAMs
 * <p>
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Piotr Kicki (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class ValidationHelper {

    private static Log log = LogFactory.getLog(ValidationHelper.class);

    // AAM configuration
    private final String deploymentId;
    private final IssuingAuthorityType deploymentType;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    private final RevokedTokensRepository revokedTokensRepository;
    private final CacheService cacheService;

    // usable
    private final RestTemplate restTemplate = new RestTemplate();
    private final String coreInterfaceAddress;
    @Value("${bat.deployment.token.validityMillis}")
    private Long tokenValidity;
    @Value("${bat.deployment.validation.allow-offline}")
    private boolean isOfflineEnough;

    @Autowired
    public ValidationHelper(CertificationAuthorityHelper certificationAuthorityHelper,
                            RevokedTokensRepository revokedTokensRepository,
                            CacheService cacheService,
                            @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getAAMInstanceIdentifier();
        this.deploymentType = certificationAuthorityHelper.getDeploymentType();
        this.revokedTokensRepository = revokedTokensRepository;
        this.cacheService = cacheService;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public ValidationStatus validate(String token
                                     //,String clientCertificate,
                                     //String clientCertificateSigningAAMCertificate,
                                     //String foreignTokenIssuingAAMCertificate
    ) {

        try {
            // basic validation (signature and exp)
            ValidationStatus validationStatus = JWTEngine.validateTokenString(token);
            if (validationStatus != ValidationStatus.VALID) {
                return validationStatus;
            }
            Claims claims = new Token(token).getClaims();
            // check revoked JTI
            if (revokedTokensRepository.exists(claims.getId())) {
                return ValidationStatus.REVOKED_TOKEN;
            }

        } catch (ValidationException e) {
            log.error(e);
            return ValidationStatus.UNKNOWN;
        }

        /** TODO
         try {

         // basic validation (signature and exp)
         ValidationStatus validationStatus = JWTEngine.validateTokenString(token);
         if (validationStatus != ValidationStatus.VALID) {
         return validationStatus;
         }

         Token tokenForValidation = new Token(token);
         if (cacheService.isValidTokenCached(tokenForValidation)) {
         return ValidationStatus.VALID;
         }

         Claims claims = tokenForValidation.getClaims();
         String spk = claims.get("spk").toString();
         String ipk = claims.get("ipk").toString();

         // check if token issued by us
         if (!deploymentId.equals(claims.getIssuer())) {
         // not our token, but the Core AAM knows things ;)
         if (deploymentType == IssuingAuthorityType.CORE
         && revokedKeysRepository.exists(claims.getIssuer()) // check if IPK is in the revoked set
         && revokedKeysRepository.findOne(claims.getIssuer()).getRevokedKeysSet().contains(ipk))
         return ValidationStatus.REVOKED_IPK;

         // relay validation to issuer
         return validateRemotelyIssuedToken(token, clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate);
         }
         // It is a token issued by us, so full checkup ahead.

         // check if issuer certificate is not expired
         if (isExpired(certificationAuthorityHelper.getAAMCertificate()))
         return ValidationStatus.EXPIRED_ISSUER_CERTIFICATE;
         // TODO possibly throw runtime exception so that AAM crashes as it is no more valid

         // check IPK is not equal to current AAM PK
         if (!Base64.getEncoder().encodeToString(
         certificationAuthorityHelper.getAAMCertificate().getPublicKey().getEncoded()).equals(ipk)) {
         return ValidationStatus.INVALID_TRUST_CHAIN;
         }

         // check revoked JTI
         if (revokedTokensRepository.exists(claims.getId())) {
         return ValidationStatus.REVOKED_TOKEN;
         }

         String userFromToken = claims.getSubject().split(FIELDS_DELIMITER)[0];

         // check if SPK is is in the revoked repository
         if (revokedKeysRepository.exists(userFromToken) && revokedKeysRepository.findOne(userFromToken).getRevokedKeysSet().contains(spk)) {
         return ValidationStatus.REVOKED_SPK;
         }

         switch (tokenForValidation.getType()) {
         case HOME:
         // check if subject certificate is valid & matching the token SPK
         switch (claims.getSubject().split(FIELDS_DELIMITER).length) {
         case 1: // local components case
         Certificate certificate = null;
         // component case - SUB/userFromToken is component name, ISS is AAM instanceId
         ComponentCertificate localComponentCertificate = componentCertificatesRepository.findOne(userFromToken);
         if (localComponentCertificate != null)
         certificate = localComponentCertificate.getCertificate();
         // if the token is to be valid, the certificate must not be null
         if (certificate == null)
         return ValidationStatus.INVALID_TRUST_CHAIN;
         // check if subject certificate is not expired
         if (isExpired(certificate.getX509())) {
         return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
         }
         // checking if SPK matches the components certificate
         if (!Base64.getEncoder().encodeToString(certificate.getX509().getPublicKey().getEncoded()).equals(spk))
         return ValidationStatus.REVOKED_SPK;
         break;
         case 2: // user token case
         String clientId = claims.getSubject().split(FIELDS_DELIMITER)[1];
         // check if we have such a user and his certificate
         if (!userRepository.exists(userFromToken)
         || !userRepository.findOne(userFromToken).getClientCertificates().containsKey(clientId))
         return ValidationStatus.INVALID_TRUST_CHAIN;
         // expiry check
         if (isExpired(userRepository.findOne(userFromToken).getClientCertificates().get(clientId).getX509())) {
         return ValidationStatus.EXPIRED_SUBJECT_CERTIFICATE;
         }
         // and if it matches the client's currently assigned cert
         if (!userRepository.exists(userFromToken) || !userRepository.findOne(userFromToken).getClientCertificates().containsKey(clientId))
         return ValidationStatus.REVOKED_SPK;
         // checking match from token
         if (!Base64.getEncoder().encodeToString(userRepository.findOne(userFromToken).getClientCertificates().get(clientId).getX509().getPublicKey().getEncoded()).equals(spk))
         return ValidationStatus.REVOKED_SPK;
         break;
         }
         break;
         case FOREIGN:
         // checking if the token is still valid against current federation definitions
         if (!validateFederationAttributes(token)) {
         revokedTokensRepository.save(tokenForValidation);
         return ValidationStatus.REVOKED_TOKEN;
         }

         // check if the foreign token origin credentials are still valid
         ValidationStatus originCredentialsValidationStatus = reachOutForeignTokenOriginCredentialsAAMToValidateThem(token);
         switch (originCredentialsValidationStatus) {
         case VALID:
         // origin credentials are valid
         cacheService.cacheValidToken(tokenForValidation);
         break;
         case UNKNOWN:
         case WRONG_AAM:
         // there was some issue with validating the origin credentials
         return originCredentialsValidationStatus;
         default:
         // we confirmed the origin credentials were invalidated and we need to invalidate our token
         revokedTokensRepository.save(tokenForValidation);
         return originCredentialsValidationStatus;
         }
         break;
         case GUEST:
         break;
         case NULL:
         break;
         default:
         break;
         }

         } catch (ValidationException
         | IOException
         | CertificateException
         | AAMException
         | NoSuchAlgorithmException
         | NoSuchProviderException e) {
         log.error(e);
         return ValidationStatus.UNKNOWN;
         }
         **/
        return ValidationStatus.VALID;
    }

    /**
     * public ValidationStatus validateRemotelyIssuedToken(String tokenString,
     * String clientCertificate,
     * String clientCertificateSigningAAMCertificate,
     * String foreignTokenIssuingAAMCertificate) throws
     * CertificateException,
     * ValidationException,
     * NoSuchAlgorithmException,
     * NoSuchProviderException,
     * IOException,
     * AAMException {
     * <p>
     * // check if already cached
     * if (cacheService.isValidTokenCached(new Token(tokenString))) {
     * return ValidationStatus.VALID;
     * }
     * <p>
     * Claims claims = JWTEngine.getClaims(tokenString);
     * //checking if token is revoked
     * if (revokedRemoteTokensRepository.exists(claims.getIssuer() + FIELDS_DELIMITER + claims.getId())) {
     * return ValidationStatus.REVOKED_TOKEN;
     * }
     * <p>
     * // if the certificate is not empty, then check the trust chain
     * if (!clientCertificate.isEmpty() && !clientCertificateSigningAAMCertificate.isEmpty()) {
     * try {
     * // foreign token needs additional trust chain validation
     * if (new Token(tokenString).getType().equals(Token.Type.FOREIGN)
     * && (foreignTokenIssuingAAMCertificate.isEmpty()
     * || !certificationAuthorityHelper.isServiceCertificateChainTrusted(foreignTokenIssuingAAMCertificate)))
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * <p>
     * // reject on failed client certificate trust chain
     * if (!isClientCertificateChainTrusted(clientCertificateSigningAAMCertificate, clientCertificate))
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * <p>
     * // reject on certificate not matching the token
     * if (!doCertificatesMatchTokenFields(
     * tokenString,
     * clientCertificate,
     * clientCertificateSigningAAMCertificate,
     * foreignTokenIssuingAAMCertificate))
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * } catch (NullPointerException npe) {
     * log.error("Problem with parsing the given PEMs string");
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * }
     * }
     * <p>
     * // resolving available AAMs in search of the token issuer
     * Map<String, AAM> availableAAMs;
     * if (!deploymentType.equals(IssuingAuthorityType.CORE)) {
     * <p>
     * AAMClient aamClient = new AAMClient(coreInterfaceAddress);
     * try {
     * availableAAMs = aamClient.getAvailableAAMs().getAvailableAAMs();
     * } catch (AAMException e) {
     * log.error(e);
     * if (isOfflineEnough)
     * return ValidationStatus.VALID;
     * else
     * return ValidationStatus.UNKNOWN;
     * }
     * // validate CoreAAM trust
     * if (!certificationAuthorityHelper.getRootCACert()
     * .equals(availableAAMs.get(SecurityConstants.CORE_AAM_INSTANCE_ID).getAamCACertificate().getCertificateString()))
     * throw new ValidationException(ValidationException.CERTIFICATE_MISMATCH);
     * } else {
     * availableAAMs = aamServices.getAvailableAAMs();
     * }
     * <p>
     * String issuer = claims.getIssuer();
     * // Core does not know such an issuer and therefore this might be a forfeit
     * if (!availableAAMs.containsKey(issuer))
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * AAM issuerAAM = availableAAMs.get(issuer);
     * String aamAddress = issuerAAM.getAamAddress();
     * <p>
     * // check ISS
     * // check if the service already has a certificate in the core
     * if (issuerAAM.getAamCACertificate().getCertificateString().isEmpty()) {
     * throw new CertificateException();
     * }
     * // checking if the certificate retrieved from the core comes from the same core as we do
     * if (!certificationAuthorityHelper.isServiceCertificateChainTrusted(issuerAAM.getAamCACertificate().getCertificateString())) {
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * }
     * <p>
     * // check IPK
     * PublicKey publicKey = issuerAAM.getAamCACertificate().getX509().getPublicKey();
     * if (!Base64.getEncoder().encodeToString(publicKey.getEncoded()).equals(claims.get("ipk"))) {
     * return ValidationStatus.INVALID_TRUST_CHAIN;
     * }
     * <p>
     * // rest check revocation
     * // preparing request
     * HttpHeaders httpHeaders = new HttpHeaders();
     * httpHeaders.add(SecurityConstants.TOKEN_HEADER_NAME, tokenString);
     * HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);
     * // checking token revocation with proper AAM
     * try {
     * ResponseEntity<ValidationStatus> status = restTemplate.postForEntity(
     * aamAddress + SecurityConstants.AAM_VALIDATE_CREDENTIALS,
     * entity, ValidationStatus.class);
     * switch (status.getBody()) {
     * case VALID:
     * cacheService.cacheValidToken(new Token(tokenString));
     * return status.getBody();
     * case UNKNOWN:
     * case WRONG_AAM:
     * // there was some issue with validating the origin credentials
     * return status.getBody();
     * default:
     * // we need to invalidate our token
     * revokedRemoteTokensRepository.save(new RevokedRemoteToken(claims.getIssuer() + FIELDS_DELIMITER + claims.getId()));
     * return status.getBody();
     * }
     * } catch (Exception e) {
     * log.error(e);
     * // when there is problem with request
     * // end procedure if offline validation is enough, certificates are ok, no connection with certificate Issuers
     * if (isOfflineEnough)
     * return ValidationStatus.VALID;
     * return null;//ValidationStatus.ISSUING_AAM_UNREACHABLE;
     * }
     * }
     * <p>
     * private boolean doCertificatesMatchTokenFields(String tokenString,
     * String clientCertificateString,
     * String clientCertificateSigningAAMCertificate,
     * String foreignTokenIssuingAAMCertificate) throws
     * IOException,
     * ValidationException,
     * CertificateException {
     * Token token = new Token(tokenString);
     * <p>
     * X509Certificate clientCertificate = CryptoHelper.convertPEMToX509(clientCertificateString);
     * // ref client certificate CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user)
     * String[] clientCommonNameFields = clientCertificate.getSubjectDN().getName().split("CN=")[1].split(FIELDS_DELIMITER);
     * if (clientCommonNameFields.length != 3)
     * return false;
     * <p>
     * X509Certificate tokenIssuerCertificate;
     * switch (token.getType()) {
     * case HOME:
     * tokenIssuerCertificate = CryptoHelper.convertPEMToX509(clientCertificateSigningAAMCertificate);
     * break;
     * case FOREIGN:
     * tokenIssuerCertificate = CryptoHelper.convertPEMToX509(foreignTokenIssuingAAMCertificate);
     * break;
     * default: // shouldn't really get here ever
     * return false;
     * }
     * String tokenIssuer = tokenIssuerCertificate.getSubjectDN().getName().split("CN=")[1];
     * PublicKey tokenIssuerKey = tokenIssuerCertificate.getPublicKey();
     * <p>
     * // ISS check
     * if (!token.getClaims().getIssuer().equals(tokenIssuer))
     * return false;
     * <p>
     * // IPK check
     * if (!token.getClaims().get("ipk").equals(Base64.getEncoder().encodeToString(tokenIssuerKey.getEncoded())))
     * return false;
     * <p>
     * // signature check
     * if (JWTEngine.validateTokenString(tokenString, tokenIssuerKey) != ValidationStatus.VALID)
     * return false;
     * <p>
     * // SPK check
     * if (!token.getClaims().get("spk").equals(Base64.getEncoder().encodeToString(clientCertificate.getPublicKey().getEncoded())))
     * return false;
     * <p>
     * // last SUB & CN check
     * switch (token.getType()) {
     * case HOME:
     * // ref client certificate CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user)
     * if (!token.getClaims().getIssuer().equals(clientCommonNameFields[2]))
     * return false;
     * // ref SUB: username@clientIdentifier
     * if (!token.getClaims().getSubject().equals(clientCommonNameFields[0] + FIELDS_DELIMITER + clientCommonNameFields[1]))
     * return false;
     * break;
     * case FOREIGN:
     * // ref SUB: username@clientIdentifier@homeAAMInstanceIdentifier
     * if (!token.getClaims().getSubject().equals(
     * clientCommonNameFields[0]
     * + FIELDS_DELIMITER
     * + clientCommonNameFields[1]
     * + FIELDS_DELIMITER
     * + CryptoHelper.convertPEMToX509(clientCertificateSigningAAMCertificate).getSubjectDN().getName().split("CN=")[1]))
     * return false;
     * break;
     * case GUEST:
     * return true;
     * case NULL:
     * // shouldn't really get here ever
     * return false;
     * }
     * <p>
     * // passed matching
     * return true;
     * }
     **/
    private boolean isExpired(X509Certificate certificate) {
        try {
            certificate.checkValidity(new Date());
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            log.info(e);
            return true;
        }
        return false;
    }

    private boolean isClientCertificateChainTrusted(String signingAAMCertificateString,
                                                    String clientCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException {

        String rootCertificate = CryptoHelper.convertX509ToPEM(certificationAuthorityHelper.getRootCACertificate());
        return CryptoHelper.isClientCertificateChainTrusted(rootCertificate, signingAAMCertificateString, clientCertificateString);
    }

}
