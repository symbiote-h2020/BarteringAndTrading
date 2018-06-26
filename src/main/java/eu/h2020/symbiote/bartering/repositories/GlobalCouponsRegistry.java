package eu.h2020.symbiote.bartering.repositories;

import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
import org.springframework.context.annotation.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Set;

/**
 * Registry of all the coupons issued in Symbiote and persisted for accounting purposes in the CoreBTM
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Profile("core")
public interface GlobalCouponsRegistry extends MongoRepository<AccountingCoupon, String> {

    Set<AccountingCoupon> findByIssuer(String issuer);

    Set<AccountingCoupon> findAllByLastConsumptionTimestampBefore(long timestamp);

    Set<AccountingCoupon> findAllByIssuerAndUseTimestampBetween(String issuer, long begin, long end);

    Set<AccountingCoupon> findAllByIssuer(String platformId);
}
