package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.repositories.RegisteredCouponRepository;
import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Set;

import static java.util.stream.Collectors.toSet;

@Profile("core")
@Service
public class CoreCouponManagementService {

    private RegisteredCouponRepository registeredCouponRepository;

    @Autowired
    public CoreCouponManagementService(RegisteredCouponRepository registeredCouponRepository) {
        this.registeredCouponRepository = registeredCouponRepository;
    }

    public int cleanupConsumedCoupons(long timestamp) {
        Set<String> registeredConsumedCouponIdsSet = registeredCouponRepository.findAllByConsumptionTimestampBefore(timestamp).stream().filter(x -> x.getStatus().equals(StoredCoupon.Status.CONSUMED)).map(RegisteredCoupon::getId).collect(toSet());
        registeredConsumedCouponIdsSet.forEach(x -> registeredCouponRepository.delete(x));
        return registeredConsumedCouponIdsSet.size();
    }
}
