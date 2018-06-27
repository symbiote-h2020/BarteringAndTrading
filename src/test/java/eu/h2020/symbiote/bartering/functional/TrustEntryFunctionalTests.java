package eu.h2020.symbiote.bartering.functional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.h2020.symbiote.bartering.AbstractBTMTestSuite;
import eu.h2020.symbiote.bartering.repositories.TrustRepository;
import eu.h2020.symbiote.cloud.trust.model.TrustEntry;
import org.junit.Before;
import org.junit.Test;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.TestPropertySource;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

@TestPropertySource("/service.properties")
public class TrustEntryFunctionalTests extends AbstractBTMTestSuite {

    @Value("${rabbit.routingKey.TrustEntry.update}")
    private String trustEntryRoutingKey;
    @Value("${rabbit.exchange.TrustEntry.update}")
    private String trustEntryExchange;

    @Autowired
    RabbitTemplate rabbitTemplate;

    @Autowired
    private TrustRepository trustRepository;

    private TrustEntry trustEntry;
    private List<TrustEntry> list;

    @Before
    public void before() {
        trustEntry = new TrustEntry(TrustEntry.Type.PLATFORM_REPUTATION, "id@1", "air quality");
        trustEntry.setValue(10.0);

        list = new ArrayList<>();
        list.add(trustEntry);
    }

    @Test
    public void newTrustEntrySuccess()
            throws JsonProcessingException, InterruptedException {
        rabbitTemplate.convertAndSend(trustEntryExchange, trustEntryRoutingKey, convertObjectToJson(list));
        //wait until rabbit listener adds federation
        Thread.sleep(1000);
        assertTrue(trustRepository.exists(trustEntry.getId()));
    }


    @Test
    public void UpdateTrustEntrySuccess()
            throws JsonProcessingException, InterruptedException {
        rabbitTemplate.convertAndSend(trustEntryExchange, trustEntryRoutingKey, convertObjectToJson(list));

        //wait until rabbit listener creates new TrustEntry
        Thread.sleep(1000);
        list.get(0).setValue(20.0);
        rabbitTemplate.convertAndSend(trustEntryExchange, trustEntryRoutingKey, convertObjectToJson(list));

        //wait until rabbit listener updates TrustEntry
        Thread.sleep(1000);
        assertEquals(trustRepository.getPREntryByPlatformId(trustEntry.getPlatformId()).getValue(), 20.0);

    }

    public String convertObjectToJson(Object obj) throws
            JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        return mapper.writeValueAsString(obj);
    }
}
