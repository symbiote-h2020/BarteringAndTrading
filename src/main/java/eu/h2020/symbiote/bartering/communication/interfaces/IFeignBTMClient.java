package eu.h2020.symbiote.bartering.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import feign.Headers;
import feign.RequestLine;
import feign.Response;

/**
 * Interface containing information about inner communications between platform BTMs
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignBTMClient {

    @RequestLine("POST " + SecurityConstants.BTM_GET_COUPON)
    @Headers("Content-Type: application/json")
    Response getCoupon(CouponRequest couponRequest);
}
