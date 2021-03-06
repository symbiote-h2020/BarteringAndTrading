package eu.h2020.symbiote.bartering;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.bartering.repositories.CouponsWallet;
import eu.h2020.symbiote.bartering.repositories.FederationsRepository;
import eu.h2020.symbiote.bartering.services.BarteredAccessManagementService;
import eu.h2020.symbiote.bartering.services.helpers.CouponIssuer;
import eu.h2020.symbiote.bartering.utils.DummyCoreAAMAndBTM;
import eu.h2020.symbiote.bartering.utils.DummyPlatformBTM;
import eu.h2020.symbiote.security.communication.BTMComponentClient;
import eu.h2020.symbiote.security.communication.IBTMComponentClient;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.SimpleMessageConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * BTM test suite stub with possibly shareable fields.
 */
@ActiveProfiles("test")
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public abstract class AbstractBTMTestSuite {

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();
    protected KeyPair userKeyPair;
    protected String dummyPlatformId = "dummy-platform";
    @Autowired
    protected CouponsWallet couponsWallet;
    @Autowired
    protected FederationsRepository federationsRepository;
    @Autowired
    protected CouponIssuer couponIssuer;
    @Autowired
    protected DummyCoreAAMAndBTM dummyCoreAAMAndBTM;
    @Autowired
    protected DummyPlatformBTM dummyPlatformBTM;
    @Autowired
    protected BarteredAccessManagementService barteredAccessManagementService;


    protected String serverAddress;
    @Value("${symbIoTe.core.interface.url:http://localhost:8443}")
    protected String coreInterfaceAddress;

    @Value("${symbIoTe.component.username}")
    protected String BTMOwnerUsername;
    @Value("${symbIoTe.component.password}")
    protected String BTMOwnerPassword;
    @Value("${symbIoTe.component.keystore.password}")
    protected String KEY_STORE_PASSWORD;
    @Value("${btm.security.PV_KEY_PASSWORD}")
    protected String PV_KEY_PASSWORD;
    @Value("${symbIoTe.component.keystore.path}")
    protected String KEY_STORE_FILE_NAME;
    @Value("${btm.security.CERTIFICATE_ALIAS}")
    protected String CERTIFICATE_ALIAS;

    protected IBTMComponentClient btmClient;
    @LocalServerPort
    private int port;

    public static X509Certificate getCertificateFromTestKeystore(String keyStoreName, String keyStorePassword, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), keyStorePassword.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    public static PrivateKey getPrivateKeyTestFromKeystore(String keyStoreName, String keyStorePassword, String pvKeyPassword, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), keyStorePassword.toCharArray());
        return (PrivateKey) pkcs12Store.getKey(certificateAlias, pvKeyPassword.toCharArray());
    }

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "http://localhost:" + port;
        btmClient = new BTMComponentClient(serverAddress);
        userKeyPair = CryptoHelper.createKeyPair();
        dummyCoreAAMAndBTM.port = port;
        // cleanup db
        couponsWallet.deleteAll();
        federationsRepository.deleteAll();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(simpleMessageConverter());
        return rabbitTemplate;
    }

    @Bean
    public SimpleMessageConverter simpleMessageConverter() {
        return new SimpleMessageConverter();
    }

    public String convertObjectToJson(Object obj) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper.writeValueAsString(obj);
    }
}