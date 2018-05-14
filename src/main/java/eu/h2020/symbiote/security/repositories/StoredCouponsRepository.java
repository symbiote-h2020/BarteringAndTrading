package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.HashSet;

/**
 * Spring repository interface definition to be used with MongoDB for operations on {@link Coupon} entities.
 *
 * @author Jakub Toczek (PSNC)
 */
@Profile("platform")
public interface StoredCouponsRepository extends MongoRepository<StoredCoupon, String> {

    HashSet<StoredCoupon> findAllByIssuer(String id);
}
