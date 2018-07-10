package eu.h2020.symbiote.bartering.services;

import eu.h2020.symbiote.bartering.config.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.bartering.repositories.GlobalCouponsRegistry;
import eu.h2020.symbiote.bartering.repositories.entities.AccountingCoupon;
import eu.h2020.symbiote.barteringAndTrading.FilterRequest;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * Used to oversee all coupons issued, exchanged and consumed in federations under this Symbiote Core
 *
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Profile("core")
@Service
public class IssuedCouponsRegistryManagementService {

    private final GlobalCouponsRegistry globalCouponsRegistry;
    private final ComponentSecurityHandlerProvider componentSecurityHandlerProvider;

    @Autowired
    public IssuedCouponsRegistryManagementService(GlobalCouponsRegistry globalCouponsRegistry,
                                                  ComponentSecurityHandlerProvider componentSecurityHandlerProvider) {
        this.globalCouponsRegistry = globalCouponsRegistry;
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
    }

    public int cleanupConsumedCoupons(long timestamp) {
        Set<String> deletedConsumedCouponsIdentifier =
                globalCouponsRegistry.findAllByLastConsumptionTimestampBefore(timestamp)
                        .stream()
                        .filter(x -> x.getStatus().equals(CouponValidationStatus.CONSUMED_COUPON))
                        .map(AccountingCoupon::getId).collect(toSet());
        deletedConsumedCouponsIdentifier.forEach(x -> globalCouponsRegistry.delete(x));
        return deletedConsumedCouponsIdentifier.size();
    }

    public CouponValidationStatus consumeCoupon(Coupon coupon) {
        long actualTimeStamp = new Date().getTime();
        CouponValidity couponValidity = isCouponValid(coupon);
        if (!couponValidity.getStatus().equals(CouponValidationStatus.VALID)) {
            return couponValidity.getStatus();
        }
        Claims claims = coupon.getClaims();
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getId(), claims.getIssuer());
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

    public boolean registerCoupon(Coupon coupon) throws
            MalformedJWTException,
            CertificateException,
            ValidationException,
            BTMException,
            SecurityHandlerException {

        JWTClaims claims = JWTEngine.getClaimsFromJWT(coupon.getCoupon());
        //checking if coupon has proper fields
        if (claims.getVal() == null
                || claims.getVal().isEmpty()
                || Long.parseLong(claims.getVal()) <= 0) {
            throw new ValidationException("CouponEntity should contain 'val' claim greater than zero");
        }
        //checking issuer public key in core
        Certificate btmCertificate = componentSecurityHandlerProvider.getComponentSecurityHandler().getSecurityHandler().getComponentCertificate("btm", claims.getIss());
        if (!claims.getIpk().equals(Base64.getEncoder().encodeToString(btmCertificate.getX509().getPublicKey().getEncoded()))) {
            throw new ValidationException("IPK from coupon doesn't match one fetched from core");
        }
        // check if id is not used
        if (globalCouponsRegistry.exists(AccountingCoupon.createIdFromNotification(claims.getJti(), claims.getIss()))) {
            throw new BTMException("CouponEntity with such id already exists.");
        }
        //save the coupon
        globalCouponsRegistry.save(new AccountingCoupon(coupon.getCoupon()));
        return true;
    }

    public CouponValidity isCouponValid(Coupon coupon) {
        long actualTimeStamp = new Date().getTime();
        Claims claims = coupon.getClaims();
        String registeredCouponId = AccountingCoupon.createIdFromNotification(claims.getId(), claims.getIssuer());
        //checking, if coupon was registered
        if (!globalCouponsRegistry.exists(registeredCouponId)) {
            return new CouponValidity(CouponValidationStatus.COUPON_NOT_REGISTERED, Coupon.Type.NULL, 0, 0);
        }
        //checking if coupon is the same as in DB
        AccountingCoupon accountingCoupon = globalCouponsRegistry.findOne(registeredCouponId);
        if (!accountingCoupon.getCouponString().equals(coupon.getCoupon())) {
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
    public Set<AccountingCoupon> getCouponStats(FilterRequest request) {
        if (/*request.federationId != null &&*/ request.beginTimestamp != null){
            return globalCouponsRegistry.findAllByIssuerAndUseTimestampBetween(
                    request.getPlatform(),
                    request.getBeginTimestamp(),
                    request.getEndTimestamp()
            );
        }else {
            return globalCouponsRegistry.findAllByIssuer(request.getPlatform());

        }
    }
}
