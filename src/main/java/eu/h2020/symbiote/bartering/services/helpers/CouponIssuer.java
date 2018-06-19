package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.bartering.config.AppConfig;
import eu.h2020.symbiote.bartering.config.ComponentSecurityHandlerProvider;
import eu.h2020.symbiote.bartering.repositories.CouponsWallet;
import eu.h2020.symbiote.bartering.repositories.entities.CouponEntity;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Used to issue coupons.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Profile("platform")
@Component
public class CouponIssuer {

    private static Log log = LogFactory.getLog(CouponIssuer.class);
    private static SecureRandom random = new SecureRandom();
    // BTM configuration
    private final ComponentSecurityHandlerProvider componentSecurityHandlerProvider;
    private final CouponsWallet couponsWallet;
    private final long periodicCouponValidity;
    private final long discreteCouponValidity;
    private final AppConfig appConfig;

    @Autowired
    public CouponIssuer(ComponentSecurityHandlerProvider componentSecurityHandlerProvider,
                        CouponsWallet couponsWallet,
                        @Value("${btm.deployment.couponEntity.periodic.validity}") long periodicCouponValidity,
                        @Value("${btm.deployment.couponEntity.discrete.validity}") long discreteCouponValidity,
                        AppConfig appConfig) {
        this.componentSecurityHandlerProvider = componentSecurityHandlerProvider;
        this.couponsWallet = couponsWallet;
        this.periodicCouponValidity = periodicCouponValidity;
        this.discreteCouponValidity = discreteCouponValidity;
        this.appConfig = appConfig;
    }

    public static String buildCouponJWS(Coupon.Type voucherType,
                                        long tokenValidity,
                                        String issuer,
                                        String federationId,
                                        PublicKey issuerPublicKey,
                                        PrivateKey issuerPrivateKey) {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        // Insert B&T Public Key
        claimsMap.put("ipk", Base64.getEncoder().encodeToString(issuerPublicKey.getEncoded()));
        // Insert B&T validity
        claimsMap.put(SecurityConstants.CLAIM_NAME_COUPON_VALIDITY, tokenValidity);
        // Insert B&T federation Id
        claimsMap.put(SecurityConstants.CLAIM_NAME_FEDERATION_ID, federationId);
        //Insert coupon type
        claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, voucherType);

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setClaims(claimsMap);
        jwtBuilder.setId(jti);
        jwtBuilder.setIssuer(issuer);
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.signWith(SignatureAlgorithm.ES256, issuerPrivateKey);

        return jwtBuilder.compact();
    }

    public Coupon getCoupon(Coupon.Type couponType, String federationId)
            throws JWTCreationException {
        try {
            if (couponType.equals(Coupon.Type.NULL))
                throw new InvalidArgumentsException("CouponEntity type can not be NULL.");
            long couponValidity = couponType.equals(Coupon.Type.PERIODIC) ? periodicCouponValidity : discreteCouponValidity;

            if (couponValidity < 1) {
                throw new InvalidArgumentsException("CouponEntity with such validity would not be valid at all.");
            }
            Coupon coupon = new Coupon(buildCouponJWS(
                    couponType,
                    couponValidity,
                    appConfig.getPlatformIdentifier(),
                    federationId,
                    componentSecurityHandlerProvider.getComponentSecurityHandler().getLocalAAMCredentials().homeCredentials.certificate.getX509().getPublicKey(),
                    componentSecurityHandlerProvider.getComponentSecurityHandler().getLocalAAMCredentials().homeCredentials.privateKey
            ));
            couponsWallet.save(new CouponEntity(coupon));
            return coupon;
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

}
