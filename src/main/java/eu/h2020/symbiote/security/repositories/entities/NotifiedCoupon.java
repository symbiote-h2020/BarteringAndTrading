package eu.h2020.symbiote.security.repositories.entities;

import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.Notification;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.springframework.data.annotation.Id;

public class NotifiedCoupon {

    @Id
    private final String id;
    private final String couponString;
    private final String issuer;
    private long issuerUsagesNotifications = 0;
    private long subjectUsagesNotifications = 0;

    public NotifiedCoupon(Notification notification) throws MalformedJWTException {
        this.id = createIdFromNotification(notification);
        this.couponString = notification.getCouponString();
        JWTClaims claims = JWTEngine.getClaimsFromJWT(notification.getCouponString());
        this.issuer = claims.getIss();
    }

    public static String createIdFromNotification(Notification notification) throws MalformedJWTException {
        JWTClaims claims = JWTEngine.getClaimsFromJWT(notification.getCouponString());
        return claims.getJti() + CryptoHelper.FIELDS_DELIMITER + claims.getIss();
    }

    public long getIssuerUsagesNotifications() {
        return issuerUsagesNotifications;
    }

    public void setIssuerUsagesNotifications(long issuerUsagesNotifications) {
        this.issuerUsagesNotifications = issuerUsagesNotifications;
    }

    public long getSubjectUsagesNotifications() {
        return subjectUsagesNotifications;
    }

    public void setSubjectUsagesNotifications(long subjectUsagesNotifications) {
        this.subjectUsagesNotifications = subjectUsagesNotifications;
    }

    public String getId() {
        return id;
    }

    public String getCouponString() {
        return couponString;
    }


    public String getIssuer() {
        return issuer;
    }
}
