package eu.h2020.symbiote.bartering.communication;

import eu.h2020.symbiote.bartering.communication.interfaces.IBTMClient;
import eu.h2020.symbiote.bartering.communication.interfaces.IFeignBTMClient;
import eu.h2020.symbiote.security.commons.exceptions.custom.BTMException;
import eu.h2020.symbiote.security.communication.ApacheCommonsLogger4Feign;
import eu.h2020.symbiote.security.communication.payloads.CouponRequest;
import feign.Feign;
import feign.FeignException;
import feign.Logger;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * REST client responsible for communication with other Bartering Trading Modules
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class BTMClient implements IBTMClient {

    private static final Log logger = LogFactory.getLog(BTMClient.class);

    private static final String BTM_COMMS_ERROR_MESSAGE = "Failed to communicate with the BTM: ";
    private String serverAddress;
    private IFeignBTMClient feignClient;

    /**
     * @param serverAddress of the Bartering Trading Module server the client wants to interact with.
     */
    public BTMClient(String serverAddress) {
        this(serverAddress, new ApacheCommonsLogger4Feign(logger));
    }

    /**
     * @param serverAddress of the Bartering Trading Module server the client wants to interact with.
     * @param logger        feign logger
     */
    public BTMClient(String serverAddress, Logger logger) {
        this.serverAddress = serverAddress;
        this.feignClient = getJsonClient(logger);
    }

    /**
     * @return Instance of feign client with all necessary parameters set
     */
    private IFeignBTMClient getJsonClient(Logger logger) {
        return Feign.builder()
                .encoder(new JacksonEncoder())
                .decoder(new JacksonDecoder())
                .logger(logger)
                .logLevel(Logger.Level.FULL)
                .target(IFeignBTMClient.class, serverAddress);
    }

    /**
     * asks other Bartering Trading Module for coupon to access the resource
     *
     * @param couponRequest request containing information about platform, type of access
     * @return Coupon coupon
     */
    @Override
    public String getCoupon(CouponRequest couponRequest) throws BTMException {
        String couponString;
        try {
            couponString = feignClient.getCoupon(couponRequest).body().toString();
        } catch (FeignException fe) {
            throw new BTMException(BTM_COMMS_ERROR_MESSAGE + fe.getMessage());
        }
        return couponString;
    }
}
