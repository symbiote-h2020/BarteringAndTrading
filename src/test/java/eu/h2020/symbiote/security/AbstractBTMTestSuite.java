package eu.h2020.symbiote.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.communication.BTMClient;
import eu.h2020.symbiote.security.communication.IBTMClient;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.ConsumedCouponsRepository;
import eu.h2020.symbiote.security.repositories.RevokedCouponsRepository;
import eu.h2020.symbiote.security.repositories.ValidCouponsRepository;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
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
 * BaT test suite stub with possibly shareable fields.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
public abstract class AbstractBTMTestSuite {

    protected final String username = "testApplicationUsername";
    protected final String clientId = "clientId";
    @Rule
    public ExpectedException expectedEx = ExpectedException.none();
    protected KeyPair userKeyPair;
    @Autowired
    protected RevokedCouponsRepository revokedCouponsRepository;
    @Autowired
    protected ValidCouponsRepository validCouponsRepository;
    @Autowired
    protected ConsumedCouponsRepository consumedCouponsRepository;


    protected ObjectMapper mapper = new ObjectMapper();
    protected String serverAddress;
    @Value("${symbIoTe.core.interface.url:https://localhost:8443}")
    protected String coreInterfaceAddress;

    @Value("${btm.deployment.owner.username}")
    protected String AAMOwnerUsername;
    @Value("${btm.deployment.owner.password}")
    protected String AAMOwnerPassword;
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

    public X509Certificate getCertificateFromTestKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (X509Certificate) pkcs12Store.getCertificate(certificateAlias);
    }

    public PrivateKey getPrivateKeyTestFromKeystore(String keyStoreName, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), KEY_STORE_PASSWORD.toCharArray());
        return (PrivateKey) pkcs12Store.getKey(certificateAlias, PV_KEY_PASSWORD.toCharArray());
    }

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "https://localhost:" + port;
        btmClient = new BTMClient(serverAddress);
        userKeyPair = CryptoHelper.createKeyPair();

        // cleanup db

        revokedCouponsRepository.deleteAll();
    }
}