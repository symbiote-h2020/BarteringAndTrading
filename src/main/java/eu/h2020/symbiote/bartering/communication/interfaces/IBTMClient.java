package eu.h2020.symbiote.bartering.communication.interfaces;

import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;

/**
 * Interface describing communication between different platform Bartering Trading Modules
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IBTMClient {
    /**
     * asks other Bartering Trading Module for coupon to access the resource
     *
     * @param couponRequest request containing information about platform, type of access
     * @return coupon string
     */
    String getCoupon(CouponRequest couponRequest) throws BTMException, ValidationException;
}
