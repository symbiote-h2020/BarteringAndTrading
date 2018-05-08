package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.NotifiedCoupon;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Set;

@Profile("core")
public interface NotificationsRepository extends MongoRepository<NotifiedCoupon, String> {

    Set<NotifiedCoupon> findByIssuer(String issuer);
}
