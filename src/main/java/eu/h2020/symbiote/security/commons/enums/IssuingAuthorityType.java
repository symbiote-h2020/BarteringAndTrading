package eu.h2020.symbiote.security.commons.enums;

/**
 * Used to define the {eu.h2020.symbiote.security.BarteringTradingManager} deployment type:
 * Core BTM,
 * Platform BTM
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public enum IssuingAuthorityType {
    /**
     * Core BTM
     */
    CORE,
    /**
     * Platform BTM
     */
    PLATFORM,
    /**
     * uninitialised value of this enum
     */
    NULL
}
