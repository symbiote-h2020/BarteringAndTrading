package eu.h2020.symbiote.bartering.config;

import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * Used by components with MongoDB
 *
 * @author Jakub Toczek
 * @author Mikołaj Dobski
 */
@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.bartering.repositories")
public class AppConfig extends AbstractMongoConfiguration {

    private final Object syncObject = new Object();
    private final String databaseName;
    private final String databaseHost;
    private final String platformId;
    private MongoClient mongoClient = null;

    @Autowired
    AppConfig(@Value("${btm.database.name}") String databaseName,
              @Value("${btm.database.host:localhost}") String databaseHost,
              @Value("${btm.platformId}") String platformId,
              ApplicationContext ctx) throws SecurityMisconfigurationException {
        this.databaseName = databaseName;
        this.databaseHost = databaseHost;
        this.platformId = platformId;

        validateSpringProfileDeploymentTypeMatch(ctx);
    }

    @Override
    protected String getDatabaseName() {
        return databaseName;
    }

    @Override
    public Mongo mongo() {
        synchronized (syncObject) {
            if (mongoClient == null) {
                mongoClient = new MongoClient(databaseHost);
            }
        }
        return mongoClient;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public String getPlatformIdentifier() {
        return platformId;
    }


    private void validateSpringProfileDeploymentTypeMatch(ApplicationContext ctx) throws
            SecurityMisconfigurationException {
        List<String> activeProfiles = new ArrayList(Arrays.asList(ctx.getEnvironment().getActiveProfiles()));
        activeProfiles.remove("test");
        switch (getDeploymentType()) {
            case CORE:
                if (!activeProfiles.get(0).equals("core")
                        || activeProfiles.size() != 1)
                    throw new SecurityMisconfigurationException("Platform identifier point to a Symbiote Core deployment. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=core'");
                break;
            case PLATFORM:
                if (!activeProfiles.get(0).equals("platform")
                        || activeProfiles.size() != 1)
                    throw new SecurityMisconfigurationException("Platform Identifier points to a platform deployment. In your bootstrap.properties, the following line must be present: 'spring.profiles.active=platform'");
                break;
            case NULL:
                throw new SecurityMisconfigurationException("Failed to resolve the BTM deployment type (CORE/PLATFORM) from the provided spring profile");
        }
    }

    private IssuingAuthorityType getDeploymentType() {
        if (getPlatformIdentifier().equals(SecurityConstants.CORE_AAM_INSTANCE_ID))
            return IssuingAuthorityType.CORE;
        return IssuingAuthorityType.PLATFORM;
    }

    /**
     * Used to define the {BarteringTradingManager} deployment type:
     * Core BTM,
     * Platform BTM
     *
     * @author Mikołaj Dobski (PSNC)
     * @author Jakub Toczek (PSNC)
     */
    private enum IssuingAuthorityType {
        /**
         * Core BTM
         */
        CORE,
        /**
         * Platform BTM
         */
        PLATFORM,
        /**
         * uninitialised value of this enum
         */
        NULL
    }

}