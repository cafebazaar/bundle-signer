package ir.cafebazaar.bundlesigner;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.apksig.SigningCertificateLineage;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
        Set<X509Certificate> seen = new HashSet<>();
        for (ApkSigner.SignerConfig signer : signers) {
            X509Certificate cert = signer.getCertificates().get(0);
            if (!lineage.isCertificateInLineage(cert)) {
                throw new ParameterException("Signer \"" + signer.getName() + "\" ("
                        + cert.getSubjectX500Principal().getName() + ") is not in the provided lineage");
            }
            if (!seen.add(cert)) {
                throw new ParameterException("Signer \"" + signer.getName() + "\" ("
                        + cert.getSubjectX500Principal().getName() + ") is specified more than once");
            }
        }
        X509Certificate oldest = lineage.getCertificatesInLineage().get(0);
        if (!seen.contains(oldest)) {
            throw new ParameterException("The oldest certificate in the lineage ("
                    + oldest.getSubjectX500Principal().getName()
                    + ") must be one of the signers; v1 and v2 are signed with it");
        }
    }
}
