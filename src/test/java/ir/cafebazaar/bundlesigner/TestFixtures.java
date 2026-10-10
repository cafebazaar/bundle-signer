package ir.cafebazaar.bundlesigner;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.apksig.ApkSignerTest;
import ir.cafebazaar.apksig.ApkVerifier;
import ir.cafebazaar.apksig.SigningCertificateLineage;
import ir.cafebazaar.apksig.internal.util.Resources;
import ir.cafebazaar.bundlesigner.command.GenBinCommand;
import ir.cafebazaar.bundlesigner.command.SignBundleCommand;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class TestFixtures {

    private static final Class<?> APKSIG = ApkSignerTest.class;
    public static final String BUNDLE = resourcePath("ir/cafebazaar/bundlesigner/bundle.aab");

    private TestFixtures() {
    }

    public static String resourcePath(String name) {
        return Objects.requireNonNull(TestFixtures.class.getClassLoader().getResource(name)).getPath();
    }

    public static ApkSigner.SignerConfig signer(String prefix) throws Exception {
        PrivateKey key = Resources.toPrivateKey(APKSIG, prefix + ".pk8");
        List<X509Certificate> certs = Resources.toCertificateChain(APKSIG, prefix + ".x509.pem");
        return new ApkSigner.SignerConfig.Builder(prefix, key, certs).build();
    }

    public static X509Certificate cert(String prefix) throws Exception {
        return Resources.toCertificate(APKSIG, prefix + ".x509.pem");
    }

    public static SigningCertificateLineage lineage(String name) throws Exception {
        return Resources.toSigningCertificateLineage(APKSIG, name);
    }

    public static File genBin(File outDir, boolean v2, boolean v3, ApkSigner.SignerConfig... signers)
            throws Exception {
        outDir.mkdirs();
        new GenBinCommand.Builder()
                .setBundle(BUNDLE)
                .setBin(outDir.getPath())
                .setSignV2Enabled(v2)
                .setSignV3Enabled(v3)
                .setSingerConfigs(Arrays.asList(signers))
                .setDebuggableApkPermitted(true)
                .build()
                .execute();
        return new File(outDir, "bundle.bin");
    }

    public static File signBundle(File bin, File outDir) throws Exception {
        new SignBundleCommand.Builder()
                .setBundle(BUNDLE)
                .setBinFile(bin.getPath())
                .setOutputPath(outDir.getPath())
                .build()
                .execute();
        return outDir;
    }

    public static ApkVerifier.Result verify(File apk) throws Exception {
        return new ApkVerifier.Builder(apk).setMinCheckedPlatformVersion(14).build().verify();
    }

    public static void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
    }
}
