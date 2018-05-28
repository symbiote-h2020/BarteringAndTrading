package eu.h2020.symbiote.bartering.repositories;

import eu.h2020.symbiote.bartering.repositories.entities.StoredCoupon;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
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

    HashSet<StoredCoupon> findAllByIssuerAndTypeAndFederationIdAndStatus(String issuer, Coupon.Type type, String federationId, CouponValidationStatus couponValidationStatus);
}
