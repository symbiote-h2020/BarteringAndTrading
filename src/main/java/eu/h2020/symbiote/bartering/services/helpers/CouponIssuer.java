package eu.h2020.symbiote.bartering.services.helpers;

import eu.h2020.symbiote.bartering.repositories.StoredCouponsRepository;
import eu.h2020.symbiote.bartering.repositories.entities.StoredCoupon;
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
    private final String deploymentId;
    private final CouponsIssuingAuthorityHelper couponsIssuingAuthorityHelper;
    @Value("${btm.deployment.coupon.periodic.validity}")
    private long periodicCouponValidity;
    @Value("${btm.deployment.coupon.discrete.validity}")
    private long discreteCouponValidity;

    private StoredCouponsRepository storedCouponsRepository;

    @Autowired
    public CouponIssuer(CouponsIssuingAuthorityHelper couponsIssuingAuthorityHelper,
                        StoredCouponsRepository storedCouponsRepository) {
        this.couponsIssuingAuthorityHelper = couponsIssuingAuthorityHelper;
        this.deploymentId = couponsIssuingAuthorityHelper.getBTMPlatformInstanceIdentifier();
        this.storedCouponsRepository = storedCouponsRepository;
    }

    public static String buildCouponJWT(Coupon.Type voucherType,
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
                throw new InvalidArgumentsException("Coupon type can not be NULL.");
            long couponValidity = couponType.equals(Coupon.Type.PERIODIC) ? periodicCouponValidity : discreteCouponValidity;

            if (couponValidity < 1) {
                throw new InvalidArgumentsException("Coupon with such validity would not be valid at all.");
            }
            Coupon coupon = new Coupon(buildCouponJWT(
                    couponType,
                    couponValidity,
                    deploymentId,
                    federationId,
                    couponsIssuingAuthorityHelper.getBTMPublicKey(),
                    couponsIssuingAuthorityHelper.getBTMPrivateKey()
            ));
            storedCouponsRepository.save(new StoredCoupon(coupon));
            return coupon;
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

}
