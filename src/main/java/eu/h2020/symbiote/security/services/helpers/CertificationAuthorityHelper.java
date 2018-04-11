package eu.h2020.symbiote.security.services.helpers;

import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityMisconfigurationException;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

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
    private static final Long CERTIFICATE_VALIDITY_PERIOD = 1L * 365L * 24L * 60L * 60L * 1000L;
    private static final String CA_FLAG_IDENTIFIER = "2.5.29.19";
    private static Log log = LogFactory.getLog(CertificationAuthorityHelper.class);
    private final X509Certificate btmCertificate;
    private final X509Certificate rootCertificationAuthorityCertificate;
    private final PrivateKey btmPrivateKey;
    private final ContentSigner contentSigner;
    private final String localAAMAddress;
    private IComponentSecurityHandler componentSecurityHandler;

    //TODO @JT change to use component security handler
    public CertificationAuthorityHelper(@Value("${btm.security.KEY_STORE_FILE_NAME}") String keyStoreFileName,
                                        @Value("${btm.security.KEY_STORE_PASSWORD}") String keyStorePassword,
                                        @Value("${btm.deployment.owner.username}") String AAMOwnerUsername,
                                        @Value("${btm.deployment.owner.password}") String AAMOwnerPassword,
                                        @Value("${symbIoTe.localaam.url}") String localAAMAddress,
                                        @Value("${btm.componentId}") String crmComponentId) throws
            SecurityMisconfigurationException,
            SecurityHandlerException,
            CertificateException {

        this.localAAMAddress = localAAMAddress;
        componentSecurityHandler = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                keyStoreFileName,
                keyStorePassword,
                crmComponentId,
                this.localAAMAddress,
                AAMOwnerUsername,
                AAMOwnerPassword
        );
        ECDSAHelper.enableECDSAProvider();
        btmCertificate = componentSecurityHandler.getLocalAAMBoundCredentials().homeCredentials.certificate.getX509();
        btmPrivateKey = componentSecurityHandler.getLocalAAMBoundCredentials().homeCredentials.privateKey;
        contentSigner = prepareContentSigner();
        rootCertificationAuthorityCertificate = componentSecurityHandler.getLocalAAMBoundCredentials().homeCredentials.homeAAM.getAamCACertificate().getX509();
    }

    /**
     * @return resolves the aam instance identifier using the AAM certificate
     */
    public String getBTMInstanceIdentifier() {
        return getAAMCertificate().getSubjectX500Principal().getName().split("CN=")[1].split(",")[0];
    }


    /**
     * @return Retrieves AAM's certificate in PEM format
     */
    public String getBTMCert() throws
            IOException {
        return CryptoHelper.convertX509ToPEM(getAAMCertificate());
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
     * @return AAM certificate in X509 format
     */
    public X509Certificate getAAMCertificate() {
        return btmCertificate;
    }

    /**
     * @return Retrieves AAM's public key from provisioned JavaKeyStore
     */
    public PublicKey getAAMPublicKey() {
        return btmCertificate.getPublicKey();
    }

    /**
     * @return retrieves AAM's private key from provisioned JavaKeyStore
     */
    public PrivateKey getAAMPrivateKey() {
        return btmPrivateKey;
    }



    private ContentSigner prepareContentSigner() throws SecurityMisconfigurationException {
        PrivateKey privKey = this.getAAMPrivateKey();
        try {
            return new JcaContentSignerBuilder(SecurityConstants.SIGNATURE_ALGORITHM).setProvider
                    (CryptoHelper.PROVIDER_NAME).build
                    (privKey);
        } catch (OperatorCreationException e) {
            log.error(e);
            throw new SecurityMisconfigurationException(e.getMessage(), e.getCause());
        }
    }

    public X509Certificate generateCertificateFromCSR(PKCS10CertificationRequest request, boolean flagCA) throws
            CertificateException {

        BasicConstraints basicConstraints;

        X509Certificate caCert;
        caCert = this.getAAMCertificate();

        JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request);

        PublicKey publicKey;
        try {
            publicKey = jcaRequest.getPublicKey();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }
        if (flagCA)
            basicConstraints = new BasicConstraints(0);
        else
            basicConstraints = new BasicConstraints(false);

        X509v3CertificateBuilder certGen;
        try {
            certGen = new JcaX509v3CertificateBuilder(
                    caCert,
                    BigInteger.valueOf(1),
                    new Date(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() + CERTIFICATE_VALIDITY_PERIOD),
                    jcaRequest.getSubject(),
                    publicKey)
                    .addExtension(
                            new ASN1ObjectIdentifier(CA_FLAG_IDENTIFIER),
                            false,
                            basicConstraints);
        } catch (CertIOException e) {
            log.error(e);
            throw new SecurityException(e.getMessage(), e.getCause());
        }


        return new JcaX509CertificateConverter()
                .setProvider(CryptoHelper.PROVIDER_NAME)
                .getCertificate(certGen
                        .build(contentSigner));
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
