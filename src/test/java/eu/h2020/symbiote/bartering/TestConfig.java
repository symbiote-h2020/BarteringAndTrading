package eu.h2020.symbiote.bartering;

import eu.h2020.symbiote.bartering.config.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

@Profile("test")
@Configuration
public class TestConfig {

    private ISecurityHandler mockedSecurityHandler;
    private IComponentSecurityHandler mockedComponentSecurityHandler;
    private String BTM_AP_NAME = "btmAPName";

    @Bean
    @Primary
    public ComponentSecurityHandlerProvider componentSecurityHandlerProvider(
            @Value("${btm.security.KEY_STORE_FILE_NAME}") String KEY_STORE_FILE_NAME,
            @Value("${btm.security.CERTIFICATE_ALIAS}") String CERTIFICATE_ALIAS,
            @Value("${btm.security.ROOT_CA_CERTIFICATE_ALIAS}") String ROOT_CERTIFICATE_ALIAS,
            @Value("${btm.security.KEY_STORE_PASSWORD}") String KEY_STORE_PASSWORD,
            @Value("${btm.security.PV_KEY_PASSWORD}") String PV_KEY_PASSWORD

    ) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            UnrecoverableKeyException, SecurityHandlerException {
        ComponentSecurityHandlerProvider componentSecurityHandlerProvider = Mockito.mock(ComponentSecurityHandlerProvider.class);
        mockedComponentSecurityHandler = Mockito.mock(IComponentSecurityHandler.class);
        when(componentSecurityHandlerProvider.getComponentSecurityHandler())
                .thenReturn(mockedComponentSecurityHandler);
        mockedSecurityHandler = Mockito.mock(ISecurityHandler.class);
        when(mockedComponentSecurityHandler.getSecurityHandler())
                .thenReturn(mockedSecurityHandler);

        Set<String> set = new HashSet<>();
        set.add(BTM_AP_NAME);
        when(mockedComponentSecurityHandler.getSatisfiedPoliciesIdentifiers(any(), any()))
                .thenReturn(set);


        AAM aam = new AAM("",
                "",
                "",
                new Certificate(
                        CryptoHelper.convertX509ToPEM(AbstractBTMTestSuite.getCertificateFromTestKeystore(
                                KEY_STORE_FILE_NAME,
                                KEY_STORE_PASSWORD,
                                ROOT_CERTIFICATE_ALIAS))),
                new HashMap<>()
        );
        HomeCredentials homeCredentials = new HomeCredentials(aam,
                "",
                "",
                new Certificate(
                        CryptoHelper.convertX509ToPEM(AbstractBTMTestSuite.getCertificateFromTestKeystore(
                                KEY_STORE_FILE_NAME,
                                KEY_STORE_PASSWORD,
                                CERTIFICATE_ALIAS))),
                AbstractBTMTestSuite.getPrivateKeyTestFromKeystore(KEY_STORE_FILE_NAME, KEY_STORE_PASSWORD, PV_KEY_PASSWORD, CERTIFICATE_ALIAS));

        when(mockedComponentSecurityHandler.getLocalAAMCredentials())
                .thenReturn(new BoundCredentials(homeCredentials));
        when(mockedComponentSecurityHandler.generateSecurityRequestUsingLocalCredentials())
                .thenReturn(new SecurityRequest(""));
        when(mockedSecurityHandler.getComponentCertificate(eq("btm"), any()))
                .thenReturn(new Certificate(
                        CryptoHelper.convertX509ToPEM(AbstractBTMTestSuite.getCertificateFromTestKeystore(
                                KEY_STORE_FILE_NAME,
                                KEY_STORE_PASSWORD,
                                CERTIFICATE_ALIAS))));

        return componentSecurityHandlerProvider;
    }
}
