package eu.h2020.symbiote.bartering.config;

import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.AbstractMongoConfiguration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


/**
 * Used by components with MongoDB
 *
 * @author Jakub Toczek
 * @author Mikołaj Dobski
 */
@Configuration
@EnableMongoRepositories("eu.h2020.symbiote.bartering.repositories")
class AppConfig extends AbstractMongoConfiguration {

    private final Object syncObject = new Object();
    private final String databaseName;
    private final String databaseHost;
    private MongoClient mongoClient = null;

    AppConfig(@Value("${btm.database.name}") String databaseName,
              @Value("${btm.database.host:localhost}") String databaseHost) {
        this.databaseName = databaseName;
        this.databaseHost = databaseHost;
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
}