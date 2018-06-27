package eu.h2020.symbiote.bartering.repositories;

import eu.h2020.symbiote.cloud.trust.model.TrustEntry;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.Date;
import java.util.List;

/**
 * @author ruggenthalerc
 * 
 *         MongoDB repository interface for trust objects providing CRUD operations.
 */
public interface TrustRepository extends MongoRepository<TrustEntry, String> {
	/**
	 * Find entries for given type and updated after a specific time.
	 * 
	 * @param updatedAfter
	 *            updated after
	 * @param type
	 *            {@link TrustEntry.Type}
	 * @return list of {@link TrustEntry}
	 */
	@Query("{'lastUpdate': {$lte: ?0}, 'type' : ?1}")
	List<TrustEntry> findEntriesUpdatedAfter(Date updatedAfter,
			TrustEntry.Type type);

	/**
	 * Get resource trust entry by given resource ID
	 * 
	 * @param resId
	 *            resource ID
	 * @return {@link TrustEntry}
	 */
	@Query("{'resourceId' : ?0, 'type' : 'RESOURCE_TRUST'}")
	TrustEntry getRTEntryByResourceId(String resId);

	/**
	 * Get platform reputation entry by given platform ID
	 * 
	 * @param platformId
	 *            platform ID
	 * @return {@link TrustEntry}
	 */
	@Query("{'platformId' : ?0, 'type' : 'PLATFORM_REPUTATION'}")
	TrustEntry getPREntryByPlatformId(String platformId);

	/**
	 * Get adaptive resource trust entry by given resource ID
	 * 
	 * @param resId
	 *            resource ID
	 * @return {@link TrustEntry}
	 */
	@Query("{'resourceId' : ?0, 'type' : 'ADAPTIVE_RESOURCE_TRUST'}")
	TrustEntry getARTEntryByResourceId(String resId);
}
