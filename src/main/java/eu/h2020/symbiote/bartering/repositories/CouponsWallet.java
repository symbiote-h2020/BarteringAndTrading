package eu.h2020.symbiote.bartering.repositories;

import eu.h2020.symbiote.bartering.repositories.entities.CouponEntity;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.HashSet;

/**
 * PlatformBTM wallet containing both issued and acquired from other platforms using bartering coupons
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("platform")
public interface CouponsWallet extends MongoRepository<CouponEntity, String> {

    HashSet<CouponEntity> findAllByIssuer(String id);

    HashSet<CouponEntity> findAllByIssuerAndTypeAndFederationIdAndStatus(String issuer,
                                                                         eu.h2020.symbiote.security.commons.Coupon.Type type,
                                                                         String federationId,
                                                                         CouponValidationStatus couponValidationStatus);
}
