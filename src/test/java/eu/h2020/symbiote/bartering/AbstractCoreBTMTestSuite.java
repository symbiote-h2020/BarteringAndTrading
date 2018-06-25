package eu.h2020.symbiote.bartering;

import eu.h2020.symbiote.bartering.repositories.GlobalCouponsRegistry;
import eu.h2020.symbiote.bartering.services.IssuedCouponsRegistryManagementService;
import eu.h2020.symbiote.bartering.utils.DummyCoreAAMAndBTM;
import eu.h2020.symbiote.security.communication.BTMComponentClient;
import eu.h2020.symbiote.security.communication.IBTMComponentClient;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
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
public abstract class AbstractCoreBTMTestSuite {

    @Autowired
    protected GlobalCouponsRegistry globalCouponsRegistry;
    @Autowired
    protected DummyCoreAAMAndBTM dummyCoreAAMAndBTM;
    @Autowired
    protected IssuedCouponsRegistryManagementService issuedCouponsRegistryManagementService;


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
    protected static final String FEDERATION_ID = "testFederationId";

    protected IBTMComponentClient btmClient;
    @LocalServerPort
    private int port;

    @BeforeClass
    public static void setupSuite() throws Exception {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    public static X509Certificate getCertificateFromTestKeystore(String keyStoreLocation, String keyStorePassword, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(keyStoreLocation), keyStorePassword.toCharArray());
        return (X509Certificate) ks.getCertificate(certificateAlias);

    }

    public static PrivateKey getPrivateKeyTestFromKeystore(String keyStoreName, String keyStorePassword, String certificateAlias) throws
            NoSuchProviderException,
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(new ClassPathResource(keyStoreName).getInputStream(), keyStorePassword.toCharArray());
        return (PrivateKey) pkcs12Store.getKey(certificateAlias, keyStorePassword.toCharArray());
    }

    @Before
    public void setUp() throws Exception {
        // Catch the random port
        serverAddress = "http://localhost:" + port;
        btmClient = new BTMComponentClient(serverAddress);
        dummyCoreAAMAndBTM.port = port;
        // cleanup db
        globalCouponsRegistry.deleteAll();
    }
}