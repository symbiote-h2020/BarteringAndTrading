package eu.h2020.symbiote.bartering.communication.interfaces;

import eu.h2020.symbiote.bartering.dto.FilterRequest;
import eu.h2020.symbiote.bartering.dto.FilterResponse;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;

import java.util.List;

/**
 * Interface describing communication to Core Bartering Trading Module
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface ICoreBTMClient {

    /**
     * Registers coupon in the Core Bartering And Trading Module
     *
     * @param couponString coupon to register
     * @return true if registration ended successfully
     */
    boolean registerCoupon(String couponString);

    /**
     * Validates, if provided coupon is registered in Core and can be still used
     *
     * @param couponString coupon for verification
     * @return CouponValidity containing all the needed information information
     * @throws InvalidArgumentsException Provided request was malformed
     * @throws WrongCredentialsException Component does not have permission to interact with Core Bartering And Trading Module
     * @throws BTMException              Internal server error occured
     */
    CouponValidity isCouponValid(String couponString) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException;

    /**
     * Consume coupon in the Core Bartering And Trading Module for granting access to federated resource
     *
     * @param couponString coupon for consumption
     * @return true, if coupon was consumed properly
     * @throws InvalidArgumentsException Provided request was malformed
     * @throws WrongCredentialsException Component does not have permission to interact with Core Bartering And Trading Module
     * @throws BTMException              Internal server error occured
     */
    boolean consumeCoupon(String couponString) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException;


    FilterResponse listCouponUsage(FilterRequest filter) throws Exception;

}
