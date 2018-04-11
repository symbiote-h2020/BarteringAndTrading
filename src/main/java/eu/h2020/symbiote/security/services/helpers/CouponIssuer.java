package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.repositories.ValidCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.ValidCoupon;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
@Component
public class CouponIssuer {

    private static Log log = LogFactory.getLog(CouponIssuer.class);
    private static SecureRandom random = new SecureRandom();
    // BTM configuration
    private final String deploymentId;
    private final CertificationAuthorityHelper certificationAuthorityHelper;
    @Value("${btm.deployment.coupon.validity}")
    private Long couponValidity;

    private ValidCouponsRepository validCouponsRepository;

    @Autowired
    public CouponIssuer(CertificationAuthorityHelper certificationAuthorityHelper,
                        ValidCouponsRepository validCouponsRepository) {
        this.certificationAuthorityHelper = certificationAuthorityHelper;
        this.deploymentId = certificationAuthorityHelper.getBTMInstanceIdentifier();
        this.validCouponsRepository = validCouponsRepository;
    }

    public static String buildCouponJWT(String subject,
                                        Map<String, String> attributes,
                                        byte[] subjectPublicKey,
                                        Coupon.Type voucherType,
                                        Long tokenValidity,
                                        String issuer,
                                        PublicKey issuerPublicKey,
                                        PrivateKey issuerPrivateKey) {
        ECDSAHelper.enableECDSAProvider();

        String jti = String.valueOf(random.nextInt());
        Map<String, Object> claimsMap = new HashMap<>();

        // Insert B&T Public Key
        claimsMap.put("ipk", Base64.getEncoder().encodeToString(issuerPublicKey.getEncoded()));
        claimsMap.put("val", tokenValidity);

        //Insert issuee Public Key
        claimsMap.put("spk", Base64.getEncoder().encodeToString(subjectPublicKey));

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
        jwtBuilder.setSubject(subject);
        jwtBuilder.setIssuedAt(new Date());
        jwtBuilder.signWith(SignatureAlgorithm.ES256, issuerPrivateKey);

        return jwtBuilder.compact();
    }

    public Coupon getDiscreteCoupon(JWTClaims claims, PublicKey componentPublicKey)
            throws JWTCreationException {
        try {
            Map<String, String> attributes = new HashMap<>();
            String subject = claims.getSub();
            Coupon coupon = new Coupon(buildCouponJWT(
                    subject,
                    attributes,
                    componentPublicKey.getEncoded(),
                    Coupon.Type.DISCRETE,
                    couponValidity,
                    deploymentId,
                    certificationAuthorityHelper.getAAMPublicKey(),
                    certificationAuthorityHelper.getAAMPrivateKey()
            ));
            validCouponsRepository.save(new ValidCoupon(coupon));
            return coupon;
        } catch (Exception e) {
            log.error(e);
            throw new JWTCreationException(e);
        }
    }

}
