package eu.h2020.symbiote.bartering.repositories;

import eu.h2020.symbiote.bartering.repositories.entities.IssuedCoupon;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Set;

@Profile("core")
public interface IssuedCouponsRegistry extends MongoRepository<IssuedCoupon, String> {

    Set<IssuedCoupon> findByIssuer(String issuer);

    Set<IssuedCoupon> findAllByLastConsumptionTimestampBefore(long timestamp);
}
