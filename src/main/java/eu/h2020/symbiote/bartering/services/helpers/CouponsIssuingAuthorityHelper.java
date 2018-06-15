package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Helper class needed by the BTMs to issue and validate coupons.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class CouponsIssuingAuthorityHelper {
    private final X509Certificate btmCertificate;
    private final PrivateKey btmPrivateKey;
    private final ApplicationContext ctx;

    public CouponsIssuingAuthorityHelper(ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                         ApplicationContext ctx) throws
            SecurityHandlerException,
            CertificateException,
            SecurityMisconfigurationException {
        ECDSAHelper.enableECDSAProvider();
        btmCertificate = componentSecurityHandlerProvider.getHomeCredentials().certificate.getX509();
        btmPrivateKey = componentSecurityHandlerProvider.getHomeCredentials().privateKey;
        this.ctx = ctx;
        validateSpringProfileDeploymentTypeMatch();
    }

    /**
     * @return resolves the deployment type using the AAM certificate
     */
    public IssuingAuthorityType getDeploymentType() {
        String btmPlatformInstanceIdentifier = getBTMPlatformInstanceIdentifier();
        if (btmPlatformInstanceIdentifier.equals(SecurityConstants.CORE_AAM_INSTANCE_ID))
            return IssuingAuthorityType.CORE;
        return IssuingAuthorityType.PLATFORM;
    }

    private void validateSpringProfileDeploymentTypeMatch() throws
            SecurityMisconfigurationException {
        List<String> activeProfiles = new ArrayList(Arrays.asList(ctx.getEnvironment().getActiveProfiles()));
        activeProfiles.remove("test");
        switch (getDeploymentType()) {
            case CORE:
                if (!activeProfiles.get(0).equals("core")
                        || activeProfiles.size() != 1)
                    throw new SecurityMisconfigurationException("The loaded certificate belongs to a Symbiote Core component. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=core'");
                break;
            case PLATFORM:
                if (!activeProfiles.get(0).equals("platform")
                        || activeProfiles.size() != 1)
                    throw new SecurityMisconfigurationException("The loaded certificate belongs to a platform component. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=platform'");
                break;
            case NULL:
                throw new SecurityMisconfigurationException("Failed to resolve the BTM deployment type (CORE/PLATFORM) from the given keystore");
        }
    }

    /**
     * @return resolves the aam instance identifier using the AAM certificate
     */
    public String getBTMInstanceIdentifier() {
        return getBTMCertificate().getSubjectX500Principal().getName().split("CN=")[1].split(",")[0];
    }

    public String getBTMPlatformInstanceIdentifier() {
        return getBTMInstanceIdentifier().split(CryptoHelper.FIELDS_DELIMITER)[1];
    }

    /**
     * @return BTM certificate in X509 format
     */
    public X509Certificate getBTMCertificate() {
        return btmCertificate;
    }

    /**
     * @return Retrieves BTM's public key from provisioned JavaKeyStore
     */
    public PublicKey getBTMPublicKey() {
        return btmCertificate.getPublicKey();
    }

    /**
     * @return retrieves BTM's private key from provisioned JavaKeyStore
     */
    public PrivateKey getBTMPrivateKey() {
        return btmPrivateKey;
    }

    /**
     * Used to define the {BarteringTradingManager} deployment type:
     * Core BTM,
     * Platform BTM
     *
     * @author Mikołaj Dobski (PSNC)
     * @author Jakub Toczek (PSNC)
     */
    public enum IssuingAuthorityType {
        /**
         * Core BTM
         */
        CORE,
        /**
         * Platform BTM
         */
        PLATFORM,
        /**
         * uninitialised value of this enum
         */
        NULL
    }
}
