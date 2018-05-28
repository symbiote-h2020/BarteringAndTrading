package eu.h2020.symbiote.bartering;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.bartering.repositories.FederationsRepository;
import eu.h2020.symbiote.bartering.repositories.StoredCouponsRepository;
import eu.h2020.symbiote.bartering.services.BarteralAccessManagementService;
import eu.h2020.symbiote.bartering.services.helpers.CertificationAuthorityHelper;
import eu.h2020.symbiote.bartering.services.helpers.CouponIssuer;
import eu.h2020.symbiote.bartering.utils.DummyCoreAAMAndBTM;
import eu.h2020.symbiote.bartering.utils.DummyPlatformBTM;
import eu.h2020.symbiote.security.communication.BTMClient;
import eu.h2020.symbiote.security.communication.IBTMClient;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.junit.Before;
import org.junit.BeforeClass;
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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
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
    protected StoredCouponsRepository storedCouponsRepository;
    @Autowired
    protected FederationsRepository federationsRepository;
    @Autowired
    protected CouponIssuer couponIssuer;
    @Autowired
    protected CertificationAuthorityHelper certificationAuthorityHelper;
    @Autowired
    protected DummyCoreAAMAndBTM dummyCoreAAMAndBTM;
    @Autowired
    protected DummyPlatformBTM dummyPlatformBTM;
    @Autowired
    protected BarteralAccessManagementService barteralAccessManagementService;


    protected String serverAddress;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    protected String coreInterfaceAddress;

    @Value("${btm.deployment.owner.username}")
    protected String BTMOwnerUsername;
    @Value("${btm.deployment.owner.password}")
    protected String BTMOwnerPassword;
    @Value("${btm.security.KEY_STORE_PASSWORD}")
    protected String KEY_STORE_PASSWORD;
    @Value("${btm.security.PV_KEY_PASSWORD}")
    protected String PV_KEY_PASSWORD;
    @Value("${btm.security.KEY_STORE_FILE_NAME}")
    protected String KEY_STORE_FILE_NAME;
    @Value("${btm.security.CERTIFICATE_ALIAS}")
    protected String CERTIFICATE_ALIAS;

    protected IBTMClient btmClient;
    @LocalServerPort
    private int port;

    @BeforeClass
    public static void setupSuite() throws Exception {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

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
        serverAddress = "https://localhost:" + port;
        btmClient = new BTMClient(serverAddress);
        userKeyPair = CryptoHelper.createKeyPair();
        dummyCoreAAMAndBTM.port = port;
        // cleanup db
        storedCouponsRepository.deleteAll();
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