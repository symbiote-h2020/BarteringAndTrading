package eu.h2020.symbiote.bartering.services;

import eu.h2020.symbiote.bartering.repositories.IssuedCouponsRegistry;
import eu.h2020.symbiote.bartering.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

@Profile("core")
@Service
public class IssuedCouponsRegistryManagementService {

    private IssuedCouponsRegistry issuedCouponsRegistry;
    private String coreInterfaceAddress;

    @Autowired
    public IssuedCouponsRegistryManagementService(IssuedCouponsRegistry issuedCouponsRegistry,
                                                  @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.issuedCouponsRegistry = issuedCouponsRegistry;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public int cleanupConsumedCoupons(long timestamp) {
        Set<String> registeredConsumedCouponIdsSet =
                issuedCouponsRegistry.findAllByLastConsumptionTimestampBefore(timestamp)
                        .stream()
                        .filter(x -> x.getStatus().equals(CouponValidationStatus.CONSUMED_COUPON))
                        .map(IssuedCoupon::getId).collect(toSet());
        registeredConsumedCouponIdsSet.forEach(x -> issuedCouponsRegistry.delete(x));
        return registeredConsumedCouponIdsSet.size();
    }

    public CouponValidationStatus consumeCoupon(String couponString) throws
            MalformedJWTException {
        long actualTimeStamp = new Date().getTime();
        CouponValidity couponValidity = isCouponValid(couponString);
        if (!couponValidity.getStatus().equals(CouponValidationStatus.VALID)) {
            return couponValidity.getStatus();
        }
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        IssuedCoupon issuedCoupon = issuedCouponsRegistry.findOne(registeredCouponId);
        // firstUsage update
        if (issuedCoupon.getFirstUseTimestamp() == 0) {
            issuedCoupon.setFirstUseTimestamp(actualTimeStamp);
        }
        issuedCoupon.setLastConsumptionTimestamp(actualTimeStamp);
        issuedCoupon.setUsagesCounter(issuedCoupon.getUsagesCounter() + 1);
        //update of DISCRETE coupons status
        if (issuedCoupon.getType().equals(Coupon.Type.DISCRETE) &&
                issuedCoupon.getUsagesCounter() >= issuedCoupon.getMaximumAllowedUsage()) {
            issuedCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        }
        issuedCouponsRegistry.save(issuedCoupon);
        return couponValidity.getStatus();
    }

    public boolean registerCoupon(String couponString) throws MalformedJWTException, AAMException, IOException, CertificateException, ValidationException, BTMException {
        //basic coupon validation
        ValidationStatus validationStatus = JWTEngine.validateJWTString(couponString);
        if (!validationStatus.equals(ValidationStatus.VALID)) {
            throw new ValidationException("Signature verification failed.");
        }
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        //checking if coupon has proper fields
        if (claims.getVal() == null
                || claims.getVal().isEmpty()
                || Long.parseLong(claims.getVal()) <= 0) {
            throw new ValidationException("Coupon should contain 'val' claim greater than zero");
        }
        //checking issuer public key in core
        AAMClient aamClient = new AAMClient(coreInterfaceAddress);
        String btmCertificate = aamClient.getComponentCertificate("btm", claims.getIss());
        if (!claims.getIpk().equals(Base64.getEncoder().encodeToString(CryptoHelper.convertPEMToX509(btmCertificate).getPublicKey().getEncoded()))) {
            throw new ValidationException("IPK from coupon doesn't match one fetched from core");
        }
        // check if id is not used
        if (issuedCouponsRegistry.exists(IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss()))) {
            throw new BTMException("Coupon with such id already exists.");
        }
        //save the coupon
        issuedCouponsRegistry.save(new IssuedCoupon(couponString));
        return true;
    }

    public CouponValidity isCouponValid(String couponString) throws MalformedJWTException {
        long actualTimeStamp = new Date().getTime();
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = IssuedCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //checking, if coupon was registered
        if (!issuedCouponsRegistry.exists(registeredCouponId)) {
            return new CouponValidity(CouponValidationStatus.COUPON_NOT_REGISTERED, Coupon.Type.NULL, 0, 0);
        }
        //checking if coupon is the same as in DB
        IssuedCoupon issuedCoupon = issuedCouponsRegistry.findOne(registeredCouponId);
        if (!issuedCoupon.getCouponString().equals(couponString)) {
            return new CouponValidity(CouponValidationStatus.DB_MISMATCH, Coupon.Type.NULL, 0, 0);
        }
        //update of the PERIODIC coupon status
        if (issuedCoupon.getStatus().equals(CouponValidationStatus.VALID) &&
                issuedCoupon.getType().equals(Coupon.Type.PERIODIC)) {

            if (issuedCoupon.getFirstUseTimestamp() != 0 &&
                    issuedCoupon.getFirstUseTimestamp() + issuedCoupon.getMaximumAllowedUsage() < actualTimeStamp) {
                issuedCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
                issuedCouponsRegistry.save(issuedCoupon);
            }
        }
        //checking status
        switch (issuedCoupon.getStatus()) {
            case VALID: {
                if (issuedCoupon.getType().equals(Coupon.Type.DISCRETE)) {
                    return new CouponValidity(CouponValidationStatus.VALID,
                            issuedCoupon.getType(),
                            issuedCoupon.getMaximumAllowedUsage() - issuedCoupon.getUsagesCounter(),
                            0);
                }
                return new CouponValidity(CouponValidationStatus.VALID,
                        issuedCoupon.getType(),
                        0,
                        issuedCoupon.getFirstUseTimestamp() == 0 ?
                                issuedCoupon.getMaximumAllowedUsage() :
                                issuedCoupon.getMaximumAllowedUsage() - (actualTimeStamp - issuedCoupon.getFirstUseTimestamp()));
            }
            default:
                return new CouponValidity(issuedCoupon.getStatus(), Coupon.Type.NULL, 0, 0);
        }
    }
}
