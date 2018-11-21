package eu.h2020.symbiote.bartering.listeners.amqp;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.bartering.services.BarteredAccessManagementService;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import java.io.IOException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.rabbit.annotation.Argument;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitHandler;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Profile("platform")
@Component
public class BarteredAccessConsumer {

    private static Log log = LogFactory.getLog(BarteredAccessConsumer.class);
    @Autowired
    AmqpTemplate amqpTemplate;
    @Autowired
    private BarteredAccessManagementService barteredAccessManagementService;

    @RabbitHandler
    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(arguments =
                    {@Argument(name = "x-message-ttl", value = "${rabbit.replyTimeout}", type = "java.lang.Integer")}),
            exchange = @Exchange(
                    value = "${rabbit.exchange.bartered.access}",
                    ignoreDeclarationExceptions = "true",
                    durable = "false",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.bartered.access}"),
            containerFactory = "noRequeueContainerFactory"
    )
    public String authorizeBarteredAccess(String message) {

        String result;
        try {
            ObjectMapper om = new ObjectMapper();
            BarteredAccessRequest barteredAccessRequest;
            barteredAccessRequest = om.readValue(message, BarteredAccessRequest.class);

            /*checking request*/
            if (barteredAccessRequest.getClientPlatform() == null ||
                    barteredAccessRequest.getClientPlatform().isEmpty() ||
                    barteredAccessRequest.getResourceId() == null ||
                    barteredAccessRequest.getResourceId().isEmpty() ||
                    barteredAccessRequest.getCouponType() == null) {
                throw new InvalidArgumentsException("BarteredAccessRequest doesn't contain all required fields.");
            }

            if (barteredAccessManagementService.authorizeBarteredAccess(barteredAccessRequest)) {
                result = String.valueOf(HttpStatus.OK);
                log.info(result);
            } else {
                result = String.valueOf(HttpStatus.BAD_REQUEST);
                log.error(result);
            }

        } catch (InvalidArgumentsException | ValidationException e) {
            result = String.valueOf(HttpStatus.BAD_REQUEST) + " : " + e.getMessage();
            log.error(result, e);
        } catch (SecurityHandlerException | BTMException e) {
            result = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR) + " : " + e.getMessage();
            log.error(result, e);
        } catch (WrongCredentialsException e) {
            result = String.valueOf(HttpStatus.UNAUTHORIZED) + " : " + e.getMessage();
            log.error(result, e);
        } catch (IOException e) {
            result = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR) + " : " + e.getMessage();
            log.error(result, e);
        }

        return result;
    }

}
