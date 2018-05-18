package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Set;

@Profile("core")
public interface RegisteredCouponRepository extends MongoRepository<RegisteredCoupon, String> {

    Set<RegisteredCoupon> findByIssuer(String issuer);

    Set<RegisteredCoupon> findAllByConsumptionTimestampBefore(long timestamp);
}
