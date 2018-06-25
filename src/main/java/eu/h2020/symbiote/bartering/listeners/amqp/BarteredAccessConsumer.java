package eu.h2020.symbiote.bartering.listeners.amqp;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.bartering.services.BarteredAccessManagementService;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.BarteredAccessRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.AmqpException;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitHandler;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Profile("platform")
@Component
public class BarteredAccessConsumer {

	private static Log log = LogFactory.getLog(BarteredAccessConsumer.class);

	@Autowired
	private BarteredAccessManagementService barteredAccessManagementService;

	@Autowired
	AmqpTemplate amqpTemplate;

	@RabbitHandler
	@RabbitListener(bindings = @QueueBinding(
			value = @Queue,
			exchange = @Exchange(
					value = "${rabbit.exchange.bartered.access}",
					ignoreDeclarationExceptions = "true",
					durable = "false",
					internal = "${rabbit.exchange.aam.internal}",
					type = "topic"),
			key = "${rabbit.routingKey.bartered.access}"))
	public void authorizeBarteredAccess(String message, @Header(AmqpHeaders.REPLY_TO) String replyTo,
			@Header(AmqpHeaders.CORRELATION_ID) String correlationId) {

		String result ="";
		try {
			ObjectMapper om = new ObjectMapper();
			BarteredAccessRequest barteredAccessRequest = null;
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
			}

			result = String.valueOf(HttpStatus.BAD_REQUEST);
			log.error(result);
		} catch (InvalidArgumentsException | ValidationException e) {
			result = String.valueOf(HttpStatus.BAD_REQUEST) +" : "+ e.getErrorMessage();
			log.error(result);
		} catch (SecurityHandlerException | BTMException e) {
			result = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR) +" : "+ e.getErrorMessage();
			log.error(result);
		} catch (WrongCredentialsException e) {
			result = String.valueOf(HttpStatus.UNAUTHORIZED) +" : "+ e.getErrorMessage();
			log.error(result);
		}catch (IOException e) {
			result = String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR) +" : "+ e.getMessage();
			log.error(result);
		}

		amqpTemplate.convertAndSend(replyTo, (Object)result, new MessagePostProcessor() {
			@Override
			public Message postProcessMessage(Message message) throws AmqpException {
				/*https://stackoverflow.com/questions/42382307/messageproperties-setcorrelationidstring-is-not-working*/
				message.getMessageProperties().setCorrelationIdString(correlationId);
				return message;
			}
		});


	}

}
