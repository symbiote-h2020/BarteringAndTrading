package eu.h2020.symbiote.bartering.commons.enums;

/**
 * Used to define the {BarteringTradingManager} deployment type:
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
