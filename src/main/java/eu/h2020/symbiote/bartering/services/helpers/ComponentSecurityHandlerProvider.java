package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Security helper class needed by the BTMs to issue and validate coupons.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class ComponentSecurityHandlerProvider {

    private final String platformId;
    private IComponentSecurityHandler componentSecurityHandler;

    @Autowired
    public ComponentSecurityHandlerProvider(@Value("${btm.security.KEY_STORE_FILE_NAME}") String keyStoreFileName,
                                            @Value("${btm.security.KEY_STORE_PASSWORD}") String keyStorePassword,
                                            @Value("${btm.deployment.owner.username}") String AAMOwnerUsername,
                                            @Value("${btm.deployment.owner.password}") String AAMOwnerPassword,
                                            @Value("${symbIoTe.localaam.url}") String localAAMAddress,
                                            @Value("${btm.platformId}") String platformId,
                                            ApplicationContext ctx) throws
            SecurityHandlerException,
            SecurityMisconfigurationException {
        this.platformId = platformId;

        componentSecurityHandler = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                keyStoreFileName,
                keyStorePassword,
                "btm@" + platformId,
                localAAMAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );

        // just to initialize the keystore
        componentSecurityHandler.generateServiceResponse();

        validateSpringProfileDeploymentTypeMatch(ctx);
    }

    public IComponentSecurityHandler getComponentSecurityHandler() {
        return componentSecurityHandler;
    }

    public HomeCredentials getHomeCredentials() throws SecurityHandlerException {
        return componentSecurityHandler.getLocalAAMCredentials().homeCredentials;
    }

    public String getPlatformIdentifier() {
        return platformId;
    }

    private void validateSpringProfileDeploymentTypeMatch(ApplicationContext ctx) throws
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

    private IssuingAuthorityType getDeploymentType() {
        if (getPlatformIdentifier().equals(SecurityConstants.CORE_AAM_INSTANCE_ID))
            return IssuingAuthorityType.CORE;
        return IssuingAuthorityType.PLATFORM;
    }

    /**
     * Used to define the {BarteringTradingManager} deployment type:
     * Core BTM,
     * Platform BTM
     *
     * @author Mikołaj Dobski (PSNC)
     * @author Jakub Toczek (PSNC)
     */
    private enum IssuingAuthorityType {
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
