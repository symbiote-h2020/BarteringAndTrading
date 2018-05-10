package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.HashSet;

/**
 * Spring repository interface definition to be used with MongoDB for operations on valid {@link Coupon} entities.
 *
 * @author Jakub Toczek (PSNC)
 */
@Profile("service")
public interface IssuedCouponsRepository extends MongoRepository<IssuedCoupon, String> {

    HashSet<IssuedCoupon> findAllByIssuer(String id);
}
