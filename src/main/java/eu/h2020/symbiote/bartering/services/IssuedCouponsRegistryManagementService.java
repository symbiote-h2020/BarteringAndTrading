package eu.h2020.symbiote.bartering.services;

import eu.h2020.symbiote.bartering.repositories.GlobalCouponsRegistry;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
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

    private GlobalCouponsRegistry globalCouponsRegistry;
    private String coreInterfaceAddress;

    @Autowired
    public IssuedCouponsRegistryManagementService(GlobalCouponsRegistry globalCouponsRegistry,
                                                  @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress) {
        this.globalCouponsRegistry = globalCouponsRegistry;
        this.coreInterfaceAddress = coreInterfaceAddress;
    }

    public int cleanupConsumedCoupons(long timestamp) {
        Set<String> registeredConsumedCouponIdsSet =
                globalCouponsRegistry.findAllByLastConsumptionTimestampBefore(timestamp)
                        .stream()
                        .filter(x -> x.getStatus().equals(CouponValidationStatus.CONSUMED_COUPON))
                        .map(AccountingCoupon::getId).collect(toSet());
        registeredConsumedCouponIdsSet.forEach(x -> globalCouponsRegistry.delete(x));
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
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        AccountingCoupon accountingCoupon = globalCouponsRegistry.findOne(registeredCouponId);
        // firstUsage update
        if (accountingCoupon.getFirstUseTimestamp() == 0) {
            accountingCoupon.setFirstUseTimestamp(actualTimeStamp);
        }
        accountingCoupon.setLastConsumptionTimestamp(actualTimeStamp);
        accountingCoupon.setUsagesCounter(accountingCoupon.getUsagesCounter() + 1);
        //update of DISCRETE coupons status
        if (accountingCoupon.getType().equals(Coupon.Type.DISCRETE) &&
                accountingCoupon.getUsagesCounter() >= accountingCoupon.getMaximumAllowedUsage()) {
            accountingCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
        }
        globalCouponsRegistry.save(accountingCoupon);
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
            throw new ValidationException("CouponEntity should contain 'val' claim greater than zero");
        }
        //checking issuer public key in core
        AAMClient aamClient = new AAMClient(coreInterfaceAddress);
        String btmCertificate = aamClient.getComponentCertificate("btm", claims.getIss());
        if (!claims.getIpk().equals(Base64.getEncoder().encodeToString(CryptoHelper.convertPEMToX509(btmCertificate).getPublicKey().getEncoded()))) {
            throw new ValidationException("IPK from coupon doesn't match one fetched from core");
        }
        // check if id is not used
        if (globalCouponsRegistry.exists(AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss()))) {
            throw new BTMException("CouponEntity with such id already exists.");
        }
        //save the coupon
        globalCouponsRegistry.save(new AccountingCoupon(couponString));
        return true;
    }

    public CouponValidity isCouponValid(String couponString) throws MalformedJWTException {
        long actualTimeStamp = new Date().getTime();
        JWTClaims claims = JWTEngine.getClaimsFromJWT(couponString);
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss());
        //checking, if coupon was registered
        if (!globalCouponsRegistry.exists(registeredCouponId)) {
            return new CouponValidity(CouponValidationStatus.COUPON_NOT_REGISTERED, Coupon.Type.NULL, 0, 0);
        }
        //checking if coupon is the same as in DB
        AccountingCoupon accountingCoupon = globalCouponsRegistry.findOne(registeredCouponId);
        if (!accountingCoupon.getCouponString().equals(couponString)) {
            return new CouponValidity(CouponValidationStatus.DB_MISMATCH, Coupon.Type.NULL, 0, 0);
        }
        //update of the PERIODIC coupon status
        if (accountingCoupon.getStatus().equals(CouponValidationStatus.VALID) &&
                accountingCoupon.getType().equals(Coupon.Type.PERIODIC)) {

            if (accountingCoupon.getFirstUseTimestamp() != 0 &&
                    accountingCoupon.getFirstUseTimestamp() + accountingCoupon.getMaximumAllowedUsage() < actualTimeStamp) {
                accountingCoupon.setStatus(CouponValidationStatus.CONSUMED_COUPON);
                globalCouponsRegistry.save(accountingCoupon);
            }
        }
        //checking status
        switch (accountingCoupon.getStatus()) {
            case VALID: {
                if (accountingCoupon.getType().equals(Coupon.Type.DISCRETE)) {
                    return new CouponValidity(CouponValidationStatus.VALID,
                            accountingCoupon.getType(),
                            accountingCoupon.getMaximumAllowedUsage() - accountingCoupon.getUsagesCounter(),
                            0);
                }
                return new CouponValidity(CouponValidationStatus.VALID,
                        accountingCoupon.getType(),
                        0,
                        accountingCoupon.getFirstUseTimestamp() == 0 ?
                                accountingCoupon.getMaximumAllowedUsage() :
                                accountingCoupon.getMaximumAllowedUsage() - (actualTimeStamp - accountingCoupon.getFirstUseTimestamp()));
            }
            default:
                return new CouponValidity(accountingCoupon.getStatus(), Coupon.Type.NULL, 0, 0);
        }
    }
}
