package eu.h2020.symbiote.bartering.communication.interfaces;


import eu.h2020.symbiote.barteringAndTrading.FilterRequest;
import eu.h2020.symbiote.barteringAndTrading.FilterResponse;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.communication.payloads.RevocationRequest;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;
import java.util.List;

/**
 * Access to services provided by Bartering and Trading module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignCoreBTMClient {

    @RequestLine("POST " + SecurityConstants.BTM_CONSUME_COUPON)
    @Headers({"Content-Type: text/plain", "Accept: text/plain",
            SecurityConstants.COUPON_HEADER_NAME + ": " + "{couponString}"})
    Response consumeCoupon(@Param("couponString") String couponString);

    @RequestLine("POST " + SecurityConstants.BTM_IS_COUPON_VALID)
    @Headers({"Content-Type: text/plain", "Accept: application/json",
            SecurityConstants.COUPON_HEADER_NAME + ": " + "{couponString}"})
    CouponValidity isCouponValid(@Param("couponString") String couponString);

    @RequestLine("POST " + SecurityConstants.BTM_REGISTER_COUPON)
    @Headers({"Content-Type: text/plain", "Accept: text/plain",
            SecurityConstants.COUPON_HEADER_NAME + ": " + "{couponString}"})
    Response registerCoupon(@Param("couponString") String couponString);

    //not implemented, interface duplicated in BTMComponentClient in SymbIoTeSecurity
    @RequestLine("POST " + SecurityConstants.BTM_REVOKE_COUPON)
    @Headers("Content-Type: application/json")
    Response revokeCoupon(RevocationRequest revocationRequest);

    //not implemented
    @RequestLine("POST " + SecurityConstants.BTM_CLEANUP_COUPONS)
    @Headers("Content-Type: text/plain")
    Response cleanupConsumedCoupons(long timestamp);

    @RequestLine("POST "+ "/couponusage")
    @Headers("Content-Type: application/json")
    List<FilterResponse> listCouponUsage(FilterRequest request);
}