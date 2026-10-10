package ir.cafebazaar.bundlesigner;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.apksig.SigningCertificateLineage;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;

final class RotationOptions {

    private RotationOptions() {
    }

    static void validate(boolean v3SigningEnabled, boolean lineageProvided, int signerCount)
            throws ParameterException {
        if (lineageProvided && !v3SigningEnabled) {
            throw new ParameterException("--lineage requires --v3-signing-enabled true");
        }
        if (lineageProvided && signerCount < 2) {
            throw new ParameterException(
                    "--lineage requires at least two signers (old and new) delimited by --next-signer");
        }
        if (!lineageProvided && signerCount > 1) {
            throw new ParameterException("Multiple signers require --lineage");
        }
    }

    static SigningCertificateLineage loadLineage(String path) throws ParameterException {
        try {
            return SigningCertificateLineage.readFromFile(new File(path));
        } catch (Exception e) {
            throw new ParameterException("Failed to read lineage file " + path + ": " + e.getMessage());
        }
    }

    static void checkSignersInLineage(SigningCertificateLineage lineage, List<ApkSigner.SignerConfig> signers)
            throws ParameterException {
        for (ApkSigner.SignerConfig signer : signers) {
            X509Certificate cert = signer.getCertificates().get(0);
            if (!lineage.isCertificateInLineage(cert)) {
                throw new ParameterException("Signer \"" + signer.getName() + "\" ("
                        + cert.getSubjectX500Principal().getName() + ") is not in the provided lineage");
            }
        }
    }
}
