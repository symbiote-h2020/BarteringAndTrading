package eu.h2020.symbiote.security.repositories;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.repositories.entities.ValidCoupon;
import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * Spring repository interface definition to be used with MongoDB for operations on valid {@link Coupon} entities.
 *
 * @author Jakub Toczek (PSNC)
 */
public interface ValidCouponsRepository extends MongoRepository<ValidCoupon, String> {
}