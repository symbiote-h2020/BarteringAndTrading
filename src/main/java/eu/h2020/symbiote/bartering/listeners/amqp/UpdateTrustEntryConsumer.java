package eu.h2020.symbiote.bartering.listeners.amqp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.bartering.repositories.TrustRepository;
import eu.h2020.symbiote.cloud.trust.model.TrustEntry;
import java.io.IOException;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.amqp.rabbit.annotation.Argument;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Profile("platform")
@Component
public class UpdateTrustEntryConsumer {

    private static Log log = LogFactory.getLog(UpdateTrustEntryConsumer.class);

    @Autowired
    private TrustRepository trustRepository;

    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(arguments =
                    {@Argument(name = "x-message-ttl", value = "${rabbit.replyTimeout}", type = "java.lang.Integer")}),
            exchange = @Exchange(
                    value = "${rabbit.exchange.TrustEntry.update}",
                    ignoreDeclarationExceptions = "true",
                    durable = "false",
                    internal = "${rabbit.exchange.aam.internal}",
                    type = "topic"),
            key = "${rabbit.routingKey.TrustEntry.update}"),
            containerFactory = "noRequeueContainerFactory"
    )
    public void updateTrustEntry(String message) {

        ObjectMapper om = new ObjectMapper();

        try {
            List<TrustEntry> list = om.readValue(message, new TypeReference<List<TrustEntry>>() {
            });

            list.forEach(te -> {
                TrustEntry entry = trustRepository.getPREntryByPlatformId(te.getPlatformId());
                if (entry != null) {
                    entry.setLastUpdate(te.getLastUpdate());
                    entry.setValue(te.getValue());
                    entry.setType(te.getType());

                    trustRepository.save(entry);
                } else
                    trustRepository.save(te);

            });

        } catch (IOException e) {
            log.error(e.getMessage());
        }

    }

}
