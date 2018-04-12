package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Certificate related set of functions.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
@Component
public class CertificationAuthorityHelper {
    private static Log log = LogFactory.getLog(CertificationAuthorityHelper.class);
    private final X509Certificate btmCertificate;
    private final X509Certificate rootCertificationAuthorityCertificate;
    private final PrivateKey btmPrivateKey;

    public CertificationAuthorityHelper(ComponentSecurityHandlerProvider componentSecurityHandlerProvider) throws
            SecurityHandlerException,
            CertificateException {
        ECDSAHelper.enableECDSAProvider();
        btmCertificate = componentSecurityHandlerProvider.getHomeCredentials().certificate.getX509();
        btmPrivateKey = componentSecurityHandlerProvider.getHomeCredentials().privateKey;
        rootCertificationAuthorityCertificate = componentSecurityHandlerProvider.getHomeCredentials().homeAAM.getAamCACertificate().getX509();
    }

    /**
     * @return resolves the aam instance identifier using the AAM certificate
     */
    public String getBTMInstanceIdentifier() {
        return getBTMCertificate().getSubjectX500Principal().getName().split("CN=")[1].split(",")[0];
    }


    /**
     * @return Retrieves AAM's certificate in PEM format
     */
    public String getBTMCert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getBTMCertificate());
    }

    /**
     * @return Retrieves RootCA's certificate in PEM format
     */
    public String getRootCACert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getRootCACertificate());
    }

    /**
     * @return RootCA certificate in X509 format
     */
    public X509Certificate getRootCACertificate() {
        return rootCertificationAuthorityCertificate;
    }

    /**
     * @return BTM certificate in X509 format
     */
    public X509Certificate getBTMCertificate() {
        return btmCertificate;
    }

    /**
     * @return Retrieves BTM's public key from provisioned JavaKeyStore
     */
    public PublicKey getBTMPublicKey() {
        return btmCertificate.getPublicKey();
    }

    /**
     * @return retrieves BTM's private key from provisioned JavaKeyStore
     */
    public PrivateKey getBTMPrivateKey() {
        return btmPrivateKey;
    }


    public boolean isServiceCertificateChainTrusted(String serviceCertificateString) throws
            NoSuchAlgorithmException,
            CertificateException,
            NoSuchProviderException,
            IOException {

        X509Certificate rootCertificate = getRootCACertificate();

        // we might be the service itself
        if (serviceCertificateString.equals(CryptoHelper.convertX509ToPEM(rootCertificate)))
            return true;

        // convert certificates to X509
        X509Certificate serviceCertificate = CryptoHelper.convertPEMToX509(serviceCertificateString);

        // Create the selector that specifies the starting certificate
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(serviceCertificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        TrustAnchor trustAnchor = new TrustAnchor(rootCertificate, null);
        trustAnchors.add(trustAnchor);

        // List of certificates to build the path from
        List<X509Certificate> certsOnPath = new ArrayList<>();
        certsOnPath.add(serviceCertificate);

        /*
         * If build() returns successfully, the certificate is valid. More details
         * about the valid path can be obtained through the PKIXCertPathBuilderResult.
         * If no valid path can be found, a CertPathBuilderException is thrown.
         */
        try {
            // Create the selector that specifies the starting certificate
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, target);
            // Disable CRL checks (this is done manually as additional step)
            params.setRevocationEnabled(false);

            // Specify a list of certificates on path
            CertStore validatedPathCertsStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certsOnPath), "BC");
            params.addCertStore(validatedPathCertsStore);

            // Build and verify the certification chain
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);
            // path should have 1 cert in symbIoTe architecture
            return result.getCertPath().getCertificates().size() == 1;
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            log.info(e);
            return false;
        }
    }
}
