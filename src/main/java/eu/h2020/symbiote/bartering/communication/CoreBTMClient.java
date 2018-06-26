package eu.h2020.symbiote.bartering.communication;

import com.google.gson.Gson;
import eu.h2020.symbiote.bartering.communication.interfaces.ICoreBTMClient;
import eu.h2020.symbiote.bartering.communication.interfaces.IFeignCoreBTMClient;
import eu.h2020.symbiote.bartering.dto.FilterRequest;
import eu.h2020.symbiote.bartering.dto.FilterResponse;
import eu.h2020.symbiote.security.clients.SymbioteComponentClientFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import feign.FeignException;
import feign.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.ArrayList;
import java.util.List;

/**
 * REST client responsible for communication with Core Bartering Trading Module
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class CoreBTMClient implements ICoreBTMClient {

    private static final Log log = LogFactory.getLog(CoreBTMClient.class);
    private final IFeignCoreBTMClient feignCoreBTMClient;
    private static final String NO_REASON_MESSAGE = "Server rejected the request.";

    public CoreBTMClient(String coreBTMAddress,
                         IComponentSecurityHandler componentSecurityHandler) throws
            SecurityHandlerException {
        this.feignCoreBTMClient = SymbioteComponentClientFactory.createClient(coreBTMAddress,
                IFeignCoreBTMClient.class,
                "btm",
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                componentSecurityHandler);
    }

    public boolean registerCoupon(String couponString) {
        Response response = this.feignCoreBTMClient.registerCoupon(couponString);
        switch (response.status()) {
            case 200:
                return true;
            case 400:
                log.error("Bad request: " + (response.reason() == null ? NO_REASON_MESSAGE : response.reason()));
                return false;
            case 401:
                log.error("Unauthorized: " + (response.reason() == null ? NO_REASON_MESSAGE : response.reason()));
                return false;
            default:
                log.error("Internal server error: " + (response.reason() == null ? NO_REASON_MESSAGE : response.reason()));
                return false; //500
        }
    }

    public CouponValidity isCouponValid(String couponString) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {
        try {
            return this.feignCoreBTMClient.isCouponValid(couponString);
        } catch (FeignException e) {
            switch (e.status()) {
                case 400:
                    throw new InvalidArgumentsException(e.getMessage());
                case 401:
                    throw new WrongCredentialsException(e.getMessage());
                default:
                    throw new BTMException(e.getMessage()); //500
            }
        }
    }

    public boolean consumeCoupon(String couponString) throws
            InvalidArgumentsException,
            WrongCredentialsException, BTMException {
        Response response = this.feignCoreBTMClient.consumeCoupon(couponString);
        switch (response.status()) {
            case 200:
                return true;
            case 400:
                throw new InvalidArgumentsException(response.reason() == null ? NO_REASON_MESSAGE : response.reason());
            case 401:
                throw new WrongCredentialsException(response.reason() == null ? NO_REASON_MESSAGE : response.reason());
            default:
                throw new BTMException(response.reason() == null ? NO_REASON_MESSAGE : response.reason()); //500
        }
    }


    public FilterResponse listCouponUsage(FilterRequest filter) throws
            InvalidArgumentsException,
            WrongCredentialsException,
            BTMException {

        try {
            log.info(this.feignCoreBTMClient.listCouponUsage(filter));
            return this.feignCoreBTMClient.listCouponUsage(filter);
        } catch (FeignException e) {
            switch (e.status()) {
            case 400:
                throw new InvalidArgumentsException(e.getMessage());
            case 401:
                throw new WrongCredentialsException(e.getMessage());
            default:
                throw new BTMException(e.getMessage()); //500
            }
        }
    }

}
