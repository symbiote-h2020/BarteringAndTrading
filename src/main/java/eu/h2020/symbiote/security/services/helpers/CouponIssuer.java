package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.repositories.IssuedCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
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
@Profile("service")
@Component
public class CouponIssuer {

    private static Log log = LogFactory.getLog(CouponIssuer.class);
    private static SecureRandom random = new SecureRandom();
    // BTM configuration
    private final String deploymentId;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    @Value("${btm.deployment.coupon.validity}")
    private long couponValidity;

    private IssuedCouponsRepository issuedCouponsRepository;

    @Autowired
    public CouponIssuer(CertificationAuthorityHelper certificationAuthorityHelper,
                        IssuedCouponsRepository issuedCouponsRepository) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getBTMInstanceIdentifier();
        this.issuedCouponsRepository = issuedCouponsRepository;
    }

    public static String buildCouponJWT(Map<String, String> attributes,
                                        Coupon.Type voucherType,
                                        long tokenValidity,
                                        String issuer,
                                        PublicKey issuerPublicKey,
                                        PrivateKey issuerPrivateKey) {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        // Insert B&T Public Key
        claimsMap.put("ipk", Base64.getEncoder().encodeToString(issuerPublicKey.getEncoded()));
        claimsMap.put("val", tokenValidity);

        //Add symbIoTe related attributes to token
        if (attributes != null && !attributes.isEmpty()) {
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                claimsMap.put(entry.getKey(), entry.getValue());
            }
        }
        //Insert token type
        claimsMap.put(SecurityConstants.CLAIM_NAME_TOKEN_TYPE, voucherType);

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setClaims(claimsMap);
        jwtBuilder.setId(jti);
        jwtBuilder.setIssuer(issuer);
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.signWith(SignatureAlgorithm.ES256, issuerPrivateKey);

        return jwtBuilder.compact();
    }

    public Coupon getDiscreteCoupon()
            throws JWTCreationException {
        try {
            Map<String, String> attributes = new HashMap<>();
            if (couponValidity < 1) {
                throw new InvalidArgumentsException("Coupon with such validity would not be valid at all.");
            }
            Coupon coupon = new Coupon(buildCouponJWT(
                    attributes,
                    Coupon.Type.DISCRETE,
                    couponValidity,
                    deploymentId,
                    certificationAuthorityHelper.getBTMPublicKey(),
                    certificationAuthorityHelper.getBTMPrivateKey()
            ));
            issuedCouponsRepository.save(new IssuedCoupon(coupon));
            return coupon;
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

}
