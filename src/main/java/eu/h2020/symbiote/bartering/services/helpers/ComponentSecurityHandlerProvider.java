package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ComponentSecurityHandlerProvider {


    private IComponentSecurityHandler componentSecurityHandler;

    public ComponentSecurityHandlerProvider(@Value("${btm.security.KEY_STORE_FILE_NAME}") String keyStoreFileName,
                                            @Value("${btm.security.KEY_STORE_PASSWORD}") String keyStorePassword,
                                            @Value("${btm.deployment.owner.username}") String AAMOwnerUsername,
                                            @Value("${btm.deployment.owner.password}") String AAMOwnerPassword,
                                            @Value("${symbIoTe.localaam.url}") String localAAMAddress,
                                            @Value("${btm.platformId}") String platformId) throws
            SecurityHandlerException {

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
    }

    public IComponentSecurityHandler getComponentSecurityHandler() {
        return componentSecurityHandler;
    }

    public HomeCredentials getHomeCredentials() throws SecurityHandlerException {
        return componentSecurityHandler.getLocalAAMCredentials().homeCredentials;
    }
}
