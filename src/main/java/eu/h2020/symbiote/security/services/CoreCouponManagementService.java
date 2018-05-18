package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.repositories.RegisteredCouponRepository;
import eu.h2020.symbiote.security.repositories.entities.RegisteredCoupon;
import eu.h2020.symbiote.security.repositories.entities.StoredCoupon;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Date;
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

    public CouponValidity isCouponValid(String couponString) throws MalformedJWTException {
        long actualTimeStamp = new Date().getTime();
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = RegisteredCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //checking, if coupon was registered
        if (!registeredCouponRepository.exists(registeredCouponId)) {
            return new CouponValidity(CouponValidationStatus.COUPON_NOT_REGISTERED, Coupon.Type.NULL, 0, 0);
        }
        //checking if coupon is the same as in DB
        RegisteredCoupon registeredCoupon = registeredCouponRepository.findOne(registeredCouponId);
        if (!registeredCoupon.getCouponString().equals(couponString)) {
            return new CouponValidity(CouponValidationStatus.DB_MISMATCH, Coupon.Type.NULL, 0, 0);
        }
        //update of the PERIODIC coupon status
        if (registeredCoupon.getStatus().equals(StoredCoupon.Status.VALID) &&
                registeredCoupon.getType().equals(Coupon.Type.PERIODIC)) {

            if (registeredCoupon.getFirstUseTimestamp() != 0 &&
                    registeredCoupon.getFirstUseTimestamp() + registeredCoupon.getValidity() < actualTimeStamp) {
                registeredCoupon.setStatus(StoredCoupon.Status.CONSUMED);
                registeredCouponRepository.save(registeredCoupon);
            }
        }
        //checking status
        switch (registeredCoupon.getStatus()) {
            case REVOKED:
                return new CouponValidity(CouponValidationStatus.REVOKED_COUPON, Coupon.Type.NULL, 0, 0);
            case CONSUMED:
                return new CouponValidity(CouponValidationStatus.CONSUMED_COUPON, Coupon.Type.NULL, 0, 0);
            default: {
                if (registeredCoupon.getType().equals(Coupon.Type.DISCRETE)) {
                    return new CouponValidity(CouponValidationStatus.VALID,
                            registeredCoupon.getType(),
                            registeredCoupon.getValidity() - registeredCoupon.getUsages(),
                            0);
                }
                return new CouponValidity(CouponValidationStatus.VALID,
                        registeredCoupon.getType(),
                        0,
                        registeredCoupon.getFirstUseTimestamp() == 0 ?
                                registeredCoupon.getValidity() :
                                registeredCoupon.getValidity() - (actualTimeStamp - registeredCoupon.getFirstUseTimestamp()));
            }
        }
    }
}
