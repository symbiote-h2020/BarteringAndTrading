package eu.h2020.symbiote.security.listeners.rest.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.communication.payloads.Notification;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Profile("core")
public interface INotifyCouponManagement {

    @PostMapping(value = SecurityConstants.BTM_NOTIFICATION, consumes = "application/json")
    ResponseEntity<String> notifyCouponManagement(@RequestBody Notification notification);

    @PostMapping(value = SecurityConstants.BTM_IS_NOTIFIED, consumes = "application/json")
    ResponseEntity<String> isNotified(@RequestBody Notification notification) throws MalformedJWTException;
}
