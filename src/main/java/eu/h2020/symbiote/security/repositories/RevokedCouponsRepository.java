package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Coupon;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on revoked {@link Coupon} entities.
 *
 * @author Jakub Toczek (PSNC)
 */
public interface RevokedCouponsRepository extends MongoRepository<Coupon, String> {
}
