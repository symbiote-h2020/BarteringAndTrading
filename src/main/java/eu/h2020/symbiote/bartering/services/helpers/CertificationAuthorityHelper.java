package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.bartering.commons.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class CertificationAuthorityHelper {
    private final X509Certificate btmCertificate;
    private final X509Certificate rootCertificationAuthorityCertificate;
    private final PrivateKey btmPrivateKey;
    private ApplicationContext ctx;

    public CertificationAuthorityHelper(ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                                        ApplicationContext ctx,
                                        @Value("${btm.platformId}") String platformId) throws
            SecurityHandlerException,
            CertificateException,
            SecurityMisconfigurationException {
        ECDSAHelper.enableECDSAProvider();
        btmCertificate = componentSecurityHandlerProvider.getHomeCredentials().certificate.getX509();
        btmPrivateKey = componentSecurityHandlerProvider.getHomeCredentials().privateKey;
        rootCertificationAuthorityCertificate = componentSecurityHandlerProvider.getHomeCredentials().homeAAM.getAamCACertificate().getX509();
        this.ctx = ctx;
        validateSpringProfileDeploymentTypeMatch();
        if (!getBTMPlatformInstanceIdentifier().equals(platformId)) {
            throw new SecurityMisconfigurationException("Platform id does not match this in provided certificate. Check btm.platformId property or check the keystore.");
        }
    }

    /**
     * @return resolves the deployment type using the AAM certificate
     */
    public IssuingAuthorityType getDeploymentType() {
        String btmInstanceIdentifier = getBTMPlatformInstanceIdentifier();
        if (btmInstanceIdentifier.equals(SecurityConstants.CORE_AAM_INSTANCE_ID))
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
                    throw new SecurityMisconfigurationException("You are loading Core certificate. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=core'");
                break;
            case PLATFORM:
                if (!activeProfiles.get(0).equals("platform")
                        || activeProfiles.size() != 1)
                    throw new SecurityMisconfigurationException("You are loading Platform certificate. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=platform'");
                break;
            case NULL:
                throw new SecurityMisconfigurationException("Failed to resolve the BTM deploymen type (CORE/PLATFORM) from the given keystore");
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
     * @return Retrieves AAM's certificate in PEM format
     */
    public String getBTMCert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getBTMCertificate());
    }

    /**
     * @return Retrieves RootCA's certificate in PEM format
     */
    public String getRootCACert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getRootCACertificate());
    }

    /**
     * @return RootCA certificate in X509 format
     */
    public X509Certificate getRootCACertificate() {
        return rootCertificationAuthorityCertificate;
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
}
