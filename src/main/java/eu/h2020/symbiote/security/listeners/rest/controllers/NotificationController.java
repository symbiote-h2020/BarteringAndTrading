package eu.h2020.symbiote.security.listeners.rest.controllers;

import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.Notification;
import eu.h2020.symbiote.security.listeners.rest.interfaces.INotifyCouponManagement;
import eu.h2020.symbiote.security.repositories.NotificationsRepository;
import eu.h2020.symbiote.security.repositories.entities.NotifiedCoupon;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Profile("core")
public class NotificationController implements INotifyCouponManagement {

    private static Log log = LogFactory.getLog(NotificationController.class);

    @Autowired
    NotificationsRepository notificationsRepository;

    /**
     * Spring controller to handle HTTPS requests related to the RESTful web services associated with notifications of the coupon creation.
     *
     * @author Jakub Toczek (PSNC)
     * @author Mikolaj Dobski (PSNC)
     * @see Notification
     * @see NotifiedCoupon
     */
    @Override
    public ResponseEntity<String> notifyCouponManagement(Notification couponManagementNotification) {
        try {
            String notificationId = NotifiedCoupon.createIdFromNotification(couponManagementNotification);
            if (!notificationsRepository.exists(notificationId)) {
                notificationsRepository.save(new NotifiedCoupon(couponManagementNotification));
                log.debug("Successfully saved information about creation of the coupon: " + notificationId);
            } else {
                NotifiedCoupon notifiedCoupon = notificationsRepository.findOne(notificationId);
                notificationsRepository.save(notifyUsage(notifiedCoupon, couponManagementNotification.getSubject()));
                log.debug("Successfully saved information about usage of the coupon: " + notificationId);
            }

            return new ResponseEntity<>(HttpStatus.OK);
        } catch (MalformedJWTException e) {
            log.error("Received coupon is malformed.");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    private NotifiedCoupon notifyUsage(NotifiedCoupon notifiedCoupon, String user) throws MalformedJWTException {
        JWTClaims claims = JWTEngine.getClaimsFromJWT(notifiedCoupon.getCouponString());
        if (user.equals(claims.getIss())) {
            notifiedCoupon.setIssuerUsagesNotifications(notifiedCoupon.getIssuerUsagesNotifications() + 1);
        } else {
            notifiedCoupon.setSubjectUsagesNotifications(notifiedCoupon.getSubjectUsagesNotifications() + 1);
        }
        return notifiedCoupon;
    }
}
