package eu.h2020.symbiote.security.unit;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.Notification;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.repositories.NotificationsRepository;
import eu.h2020.symbiote.security.repositories.entities.NotifiedCoupon;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;

import static eu.h2020.symbiote.security.services.helpers.CouponIssuer.buildCouponJWT;
import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ContextConfiguration
@TestPropertySource("/core.properties")
public class CouponNotificationUnitTests {


    @Autowired
    NotificationsRepository notificationsRepository;
    private RestTemplate restTemplate = new RestTemplate();
    private String dummyPlatformId = "dummyPlatformId";
    private String serverAddress;
    @LocalServerPort
    private int port;
    private KeyPair userKeyPair;

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

    @Before
    public void before() throws
            InvalidAlgorithmParameterException,
            NoSuchAlgorithmException,
            NoSuchProviderException {
        serverAddress = "https://localhost:" + port;
        userKeyPair = CryptoHelper.createKeyPair();
        notificationsRepository.deleteAll();
    }


    @Test
    public void receivedCreationNotificationSuccess() throws
            ValidationException,
            MalformedJWTException {
        //get any coupon for notification
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        //check if notification repo is empty
        assertEquals(0, notificationsRepository.count());

        //create and send notification
        Notification notification = new Notification(coupon.getCoupon(), dummyPlatformId);
        System.out.println(serverAddress + SecurityConstants.BTM_NOTIFICATION);
        //Thread.sleep(10000000);
        ResponseEntity<String> notificationResponse = restTemplate.postForEntity(
                serverAddress + SecurityConstants.BTM_NOTIFICATION,
                notification, String.class);

        assertEquals(HttpStatus.OK, notificationResponse.getStatusCode());
        assertEquals(1, notificationsRepository.count());
        NotifiedCoupon notifiedCoupon = notificationsRepository.findOne(NotifiedCoupon.createIdFromNotification(notification));
        assertNotNull(notifiedCoupon);
        assertEquals(coupon.getCoupon(), notifiedCoupon.getCouponString());
        assertEquals(0, notifiedCoupon.getIssuerUsagesNotifications());
        assertEquals(0, notifiedCoupon.getSubjectUsagesNotifications());
        assertEquals(dummyPlatformId, notifiedCoupon.getIssuer());
    }

    @Test
    public void receivedUsageNotificationSuccess() throws
            ValidationException,
            MalformedJWTException {
        //get any coupon for notification
        Coupon coupon = new Coupon(buildCouponJWT(
                new HashMap<>(),
                Coupon.Type.DISCRETE,
                100,
                dummyPlatformId,
                //for now, doesnt matter what the keys are
                userKeyPair.getPublic(),
                userKeyPair.getPrivate()
        ));
        //create notification
        Notification notification = new Notification(coupon.getCoupon(), dummyPlatformId);

        notificationsRepository.save(new NotifiedCoupon(notification));
        //check if notification repo contains notification
        assertEquals(1, notificationsRepository.count());

        System.out.println(serverAddress + SecurityConstants.BTM_NOTIFICATION);

        //send notification
        ResponseEntity<String> notificationResponse = restTemplate.postForEntity(
                serverAddress + SecurityConstants.BTM_NOTIFICATION,
                notification, String.class);

        assertEquals(HttpStatus.OK, notificationResponse.getStatusCode());
        assertEquals(1, notificationsRepository.count());
        NotifiedCoupon notifiedCoupon = notificationsRepository.findOne(NotifiedCoupon.createIdFromNotification(notification));
        assertNotNull(notifiedCoupon);
        assertEquals(coupon.getCoupon(), notifiedCoupon.getCouponString());
        assertEquals(1, notifiedCoupon.getIssuerUsagesNotifications());
        assertEquals(0, notifiedCoupon.getSubjectUsagesNotifications());
        assertEquals(dummyPlatformId, notifiedCoupon.getIssuer());

        //send notification by another platform than issuer
        notification = new Notification(coupon.getCoupon(), "otherPlatform");
        notificationResponse = restTemplate.postForEntity(
                serverAddress + SecurityConstants.BTM_NOTIFICATION,
                notification, String.class);

        assertEquals(HttpStatus.OK, notificationResponse.getStatusCode());
        assertEquals(1, notificationsRepository.count());
        notifiedCoupon = notificationsRepository.findOne(NotifiedCoupon.createIdFromNotification(notification));
        assertNotNull(notifiedCoupon);
        assertEquals(coupon.getCoupon(), notifiedCoupon.getCouponString());
        assertEquals(1, notifiedCoupon.getIssuerUsagesNotifications());
        assertEquals(1, notifiedCoupon.getSubjectUsagesNotifications());
        assertEquals(dummyPlatformId, notifiedCoupon.getIssuer());

    }

    @Test
    public void receivedNotificationFailMalformedCoupon() {
        //check if notification repo is empty
        assertEquals(0, notificationsRepository.count());

        //create and send notification
        Notification notification = new Notification("MalformedCoupon", dummyPlatformId);
        try {
            restTemplate.postForEntity(
                    serverAddress + SecurityConstants.BTM_NOTIFICATION,
                    notification, String.class);
            fail();
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.BAD_REQUEST, e.getStatusCode());
        }
    }
}
