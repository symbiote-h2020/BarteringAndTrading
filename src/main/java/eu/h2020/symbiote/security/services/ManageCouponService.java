package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.*;
import eu.h2020.symbiote.security.commons.jwt.JWTClaims;
import eu.h2020.symbiote.security.commons.jwt.JWTEngine;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.Notification;
import eu.h2020.symbiote.security.repositories.IssuedCouponsRepository;
import eu.h2020.symbiote.security.repositories.entities.IssuedCoupon;
import eu.h2020.symbiote.security.services.helpers.CouponIssuer;
import eu.h2020.symbiote.security.services.helpers.ValidationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashSet;
import java.util.Map;

/**
 * Spring service used to provide token related functionality of the BAT.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
@Profile("service")
@Service
public class ManageCouponService {

    private static final String BTM_SUFFIX = "/btm";
    private static Log log = LogFactory.getLog(ManageCouponService.class);
    private final CouponIssuer couponIssuer;
    private final String coreInterfaceAddress;
    private final ValidationHelper validationHelper;
    private final String btmCoreAddress;
    private final String platformId;
    private final IssuedCouponsRepository issuedCouponsRepository;
    private RestTemplate restTemplate = new RestTemplate();


    @Autowired
    public ManageCouponService(CouponIssuer couponIssuer,
                               @Value("${symbIoTe.core.interface.url}") String coreInterfaceAddress,
                               @Value("${btm.platformId}") String platformId,
                               ValidationHelper validationHelper,
                               IssuedCouponsRepository issuedCouponsRepository) {
        this.couponIssuer = couponIssuer;
        this.coreInterfaceAddress = coreInterfaceAddress;
        this.btmCoreAddress = coreInterfaceAddress.endsWith("/aam") ? coreInterfaceAddress.substring(0, coreInterfaceAddress.length() - 4) + BTM_SUFFIX : coreInterfaceAddress + BTM_SUFFIX;
        this.platformId = platformId;
        this.validationHelper = validationHelper;
        this.issuedCouponsRepository = issuedCouponsRepository;
    }

    public Coupon sendCouponForExchange(String btmAddress, Coupon localCoupon) throws BTMException, ValidationException {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(SecurityConstants.COUPON_HEADER_NAME, localCoupon.getCoupon());
        HttpEntity<String> entity = new HttpEntity<>(null, httpHeaders);
        ResponseEntity<String> exchangeResponse;
        try {
            exchangeResponse = restTemplate.postForEntity(
                    btmAddress + SecurityConstants.BTM_EXCHANGE_COUPONS,
                    entity, String.class);
        } catch (HttpServerErrorException | HttpClientErrorException e) {
            if (e.getStatusCode().equals(HttpStatus.FORBIDDEN)) {
                throw new BTMException("Federated BTM refused to exchange coupons.");
            }
            throw new BTMException("Federated BTM is unavailable.");
        }
        String coupon = exchangeResponse.getHeaders().get(SecurityConstants.COUPON_HEADER_NAME).get(0);
        return new Coupon(coupon);
    }

    private boolean notifyCore(Coupon localCoupon) {
        Notification notification = new Notification(localCoupon.getCoupon(), platformId);
        ResponseEntity<String> notificationResponse;
        try {
            notificationResponse = restTemplate.postForEntity(
                    btmCoreAddress + SecurityConstants.BTM_NOTIFICATION,
                    notification, String.class);
        } catch (Exception e) {
            log.error(e.getMessage());
            return false;
        }
        return notificationResponse.getStatusCode().equals(HttpStatus.OK);
    }

    public Coupon getCoupon(String loginRequest) throws
            MalformedJWTException,
            InvalidArgumentsException,
            JWTCreationException,
            ValidationException,
            BTMException {
        // validate request
        JWTClaims claims = JWTEngine.getClaimsFromJWT(loginRequest);

        if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
            throw new InvalidArgumentsException();
        }
        //TODO ISS check
        //search for saved coupons
        HashSet<IssuedCoupon> issuedCoupons = issuedCouponsRepository.findAllByIssuer(claims.getSub());
        if (issuedCoupons.isEmpty()) {
            return getFederatedCoupon(claims);
        } else {
            for (IssuedCoupon issuedCoupon : issuedCoupons) {
                if (issuedCoupon.getStatus().equals(IssuedCoupon.Status.VALID))
                    return new Coupon(issuedCoupon.getCouponString());
            }
            return getFederatedCoupon(claims);
        }

    }

    private Coupon getFederatedCoupon(JWTClaims claims) throws ValidationException, JWTCreationException, BTMException {
        // search for federated btm
        Map<String, AAM> availableAAMs = getAvailableAAMs();
        if (!availableAAMs.containsKey(claims.getSub())) {
            throw new ValidationException("Platform url is not achievable. Check, if platform is registered in Core.");
        }
        String aamAddress = availableAAMs.get(claims.getSub()).getAamAddress();
        String btmAddress = aamAddress.endsWith("/aam") ? aamAddress.substring(0, aamAddress.length() - 4) + BTM_SUFFIX : aamAddress + BTM_SUFFIX;

        // generate coupon for exchange
        Coupon coupon = couponIssuer.getDiscreteCoupon();
        // notify Core BTM about creation of coupon
        if (!notifyCore(coupon)) {
            throw new BTMException("Problem with notification to Core about coupon creation occurred.");
        }
        //exchange coupon
        Coupon exchangedCoupon = sendCouponForExchange(btmAddress, coupon);
        issuedCouponsRepository.save(new IssuedCoupon(exchangedCoupon));
        return exchangedCoupon;
    }

    private Map<String, AAM> getAvailableAAMs() throws BTMException {
        AAMClient aamClient = new AAMClient(coreInterfaceAddress);
        Map<String, AAM> availableAAMs;
        try {
            availableAAMs = aamClient.getAvailableAAMs().getAvailableAAMs();
        } catch (AAMException e) {
            log.error(e);
            throw new BTMException("Core AAM is not available. Please, check your connection.");
        }
        return availableAAMs;
    }

    /*
        public Coupon TODOvalidation(String loginRequest) throws
                MalformedJWTException,
                InvalidArgumentsException,
                JWTCreationException,
                ValidationException,
                IOException,
                CertificateException {
            // validate request
            JWTClaims claims = JWTEngine.getClaimsFromJWT(loginRequest);

            if (claims.getIss() == null || claims.getSub() == null || claims.getIss().isEmpty() || claims.getSub().isEmpty()) {
                throw new InvalidArgumentsException();
            }

            String componentCertificate;
            AAMClient aamClient = new AAMClient(coreInterfaceAddress);
            try {
                componentCertificate = aamClient.getComponentCertificate(claims.getSub(), claims.getIss());
            } catch (AAMException e) {
                log.error(e);
                throw new ValidationException("Core AAM is not available. Please, check your connection.");
            }
            PublicKey componentPublicKey = CryptoHelper.convertPEMToX509(componentCertificate).getPublicKey();
            if (ValidationStatus.VALID != JWTEngine.validateJWTString(loginRequest, componentPublicKey)) {
                String message = String.format("Certificate public key of %s mismatch with this acquired from %s", claims.getSub(), claims.getIss());
                log.error(message);
                throw new ValidationException(message);
            }
            return couponIssuer.getDiscreteCoupon();
        }
    */
    public boolean consumeCoupon(String couponString) throws
            MalformedJWTException,
            InvalidArgumentsException,
            ValidationException,
            BTMException {
        Coupon coupon = new Coupon(couponString);
        // validate coupon
        if (!validationHelper.validate(couponString).equals(CouponValidationStatus.VALID)) {
            throw new InvalidArgumentsException("Coupon is not valid.");
        }
        IssuedCoupon issuedCoupon = issuedCouponsRepository.findOne(coupon.getId());
        if (new Coupon(issuedCoupon.getCouponString()).getType().equals(Coupon.Type.DISCRETE)) {
            long validity = issuedCoupon.getValidity();
            if (validity <= 1) {
                issuedCoupon.setStatus(IssuedCoupon.Status.CONSUMED);
            }
            issuedCoupon.setValidity(validity - 1);
            issuedCouponsRepository.save(issuedCoupon);

            if (!notifyCore(coupon)) {
                throw new BTMException("Problem with notification to Core about coupon usage occurred.");
            }
            return true;
        }

        //TODO add PERIODIC coupon
        return false;

    }

    /**
     * @param couponString received coupon for exchange
     * @return exchanged coupon
     * @throws ValidationException  received coupon is not valid
     * @throws JWTCreationException received coupon is malformed and wasn't processed
     * @throws BTMException         error during Core notification occured
     */
    public Coupon exchangeCoupon(String couponString) throws
            ValidationException,
            JWTCreationException,
            BTMException {
        Coupon receivedCoupon = new Coupon(couponString);
        //TODO validate in core
        //TODO validate B&T deal / if exchange refused, HttpStatus.Forbiden
        // generate coupon for exchange
        Coupon coupon = couponIssuer.getDiscreteCoupon();
        // notify core about creation of the coupon
        if (!notifyCore(coupon)) {
            throw new BTMException("Problem with notification to Core about coupon creation occurred.");
        }
        // save exchanged coupon
        issuedCouponsRepository.save(new IssuedCoupon(coupon));
        // save received coupon
        issuedCouponsRepository.save(new IssuedCoupon(receivedCoupon));
        return coupon;

    }
}
