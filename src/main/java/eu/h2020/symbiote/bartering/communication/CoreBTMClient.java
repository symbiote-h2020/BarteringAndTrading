package eu.h2020.symbiote.bartering.communication;

import eu.h2020.symbiote.security.clients.SymbioteComponentClientFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.payloads.CouponValidity;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import feign.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CoreBTMClient {

    private final static Log log = LogFactory.getLog(CoreBTMClient.class);
    private final IFeignCoreBTMClient feignCoreBTMClient;

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
                log.error("Bad request: " + response.reason());
                return false;
            case 401:
                log.error("Unauthorized: " + response.reason());
                return false;
            default:
                log.error("Internal server error: " + response.reason());
                return false; //500
        }
    }

    //TODO
    public CouponValidity isCouponValid(String couponString) {
        return this.feignCoreBTMClient.isCouponValid(couponString);
    }

    public boolean consumeCoupon(String couponString) throws
            InvalidArgumentsException,
            WrongCredentialsException, BTMException {
        Response response = this.feignCoreBTMClient.consumeCoupon(couponString);
        switch (response.status()) {
            case 200:
                return true;
            case 400:
                throw new InvalidArgumentsException(response.reason());
            case 401:
                throw new WrongCredentialsException(response.reason());
            default:
                throw new BTMException(response.reason()); //500
        }
    }


}
