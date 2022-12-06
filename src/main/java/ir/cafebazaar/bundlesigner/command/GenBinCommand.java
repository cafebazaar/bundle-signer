package ir.cafebazaar.bundlesigner.command;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.bundlesigner.BundleToolWrapper;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;
import org.apache.log4j.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static ir.cafebazaar.bundlesigner.BundleSignerTool.TMP_DIR_PATH;

public class GenBinCommand {

    private final File bundle;
    private final File bin;
    private final boolean signV2Enabled;
    private final boolean signV3Enabled;
    private final boolean debuggableApkPermitted;
    private final List<ApkSigner.SignerConfig> signerConfigs;
    private final int minSdkVersion;
    private final boolean minSdkVersionSpecified;
    private final boolean verbose;

    private static final Logger logger = Logger.getLogger(String.valueOf(GenBinCommand.class));


    private GenBinCommand(File bundle, File bin, boolean signV2Enabled, boolean signV3Enabled, boolean permitted,
                          List<ApkSigner.SignerConfig> signerConfigs, int version, boolean minSdkVersionSpecified,
                          boolean verbose) {
        this.bin = bin;
        this.bundle = bundle;
        this.verbose = verbose;
        this.signV2Enabled = signV2Enabled;
        this.signV3Enabled = signV3Enabled;
        this.signerConfigs = signerConfigs;
        this.minSdkVersionSpecified = minSdkVersionSpecified;
        debuggableApkPermitted = permitted;
        minSdkVersion = version;
    }


    public static class Builder {

        private static File bundle;
        private static String binFilePath;
        private static boolean signV2Enabled;
        private static boolean signV3Enabled;
        private static boolean debuggableApkPermitted;
        private static List<ApkSigner.SignerConfig> signerConfigs;
        private static int minSdkVersion;
        private static boolean minSdkVersionSpecified;
        private static boolean verbose;


        public GenBinCommand.Builder setBundle(String bundlePath) {
            bundle = new File(bundlePath);
            return this;
        }

        public GenBinCommand.Builder setBin(String binPath) {
            binFilePath = binPath;
            return this;
        }

        public GenBinCommand.Builder setSignV2Enabled(boolean enabled) {
            signV2Enabled = enabled;
            return this;
        }

        public GenBinCommand.Builder setSignV3Enabled(boolean enabled) {
            signV3Enabled = enabled;
            return this;
        }

        public GenBinCommand.Builder setDebuggableApkPermitted(boolean permitted) {
            debuggableApkPermitted = permitted;
            return this;
        }

        public GenBinCommand.Builder setSingerConfigs(List<ApkSigner.SignerConfig> signerConfigs) {
            Builder.signerConfigs = signerConfigs;
            return this;
        }

        public GenBinCommand.Builder setMinSdkVersion(int version) {
            minSdkVersion = version;
            return this;
        }

        public GenBinCommand.Builder setMinSdkVersionSpecified(boolean specified) {
            minSdkVersionSpecified = specified;
            return this;
        }

        public GenBinCommand.Builder setVerbose(boolean verbose) {
            Builder.verbose = verbose;
            return this;
        }

        public GenBinCommand build() throws IOException {

            if (bundle == null)
                return null;

            String binFileName = bundle.getName().split("\\.")[0] + ".bin";
            File bin = new File(binFilePath + File.separator + binFileName);

            return new GenBinCommand(bundle, bin, signV2Enabled, signV3Enabled, debuggableApkPermitted, signerConfigs,
                    minSdkVersion, minSdkVersionSpecified, verbose);
        }
    }

    public void execute() throws Exception {
        logger.info("started genbin command.");
        String apksPath = BundleToolWrapper.buildApkSet(bundle, TMP_DIR_PATH, false);
        String universalPath = BundleToolWrapper.buildApkSet(bundle, TMP_DIR_PATH, true);
        System.gc();

        File binV1 = new File(TMP_DIR_PATH + File.separator + "binv1");
        File binV2V3 = new File(TMP_DIR_PATH + File.separator + "binv2_v3");

        extractAndSignApkSet(apksPath, binV1, binV2V3);
        extractAndSignApkSet(universalPath, binV1, binV2V3);

        generateFinalBinFile(binV1, binV2V3);

        if (verbose) {
            System.out.println(String.format("Digest content generated. Bin file saved in %s .", bin.getPath()));
        }
        logger.info("File generated.");
    }

    private void extractAndSignApkSet(String apksPath, File binV1, File binV2V3) throws Exception {
        ZipFile apkZip = new ZipFile(apksPath);
        apkZip.extractAll(TMP_DIR_PATH);
        logger.info("Extracted apk set.");

        List<FileHeader> apkSetEntries = apkZip.getFileHeaders();

        for (FileHeader apkSetEntry : apkSetEntries) {
            if (!apkSetEntry.getFileName().contains("apk")) {
                continue;
            }
            logger.info("signing " + apkSetEntry.getFileName());

            File apk = new File(TMP_DIR_PATH + File.separator + apkSetEntry.getFileName());
            new File(apk.getParent()).mkdirs();

            String apkName = apkSetEntry.getFileName().split(".apk")[0] + ".apk";
            apkName = apkName.replace("/", "_");

            calculateSignOfApk(apkName, binV1, binV2V3, apk);
            logger.info("signed " + apkSetEntry.getFileName());
        }
    }

    private void calculateSignOfApk(String apkName, File binV1, File binV2V3, File apk) throws Exception {

        ApkSigner.Builder apkSignerBuilder =
                new ApkSigner.Builder(new ArrayList<>(0), true)
                        .setInputApk(apk)
                        .setOtherSignersSignaturesPreserved(false)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(signV2Enabled)
                        .setV3SigningEnabled(signV3Enabled)
                        .setDebuggableApkPermitted(debuggableApkPermitted);
        if (minSdkVersionSpecified) {
            apkSignerBuilder.setMinSdkVersion(minSdkVersion);
        }

        ApkSigner apkSigner = apkSignerBuilder.build();
        String digest = apkSigner.genV1Bin();

        apkSignerBuilder = new ApkSigner.Builder(signerConfigs)
                .setSignDigest(apk.getPath(), digest);

        apkSigner = apkSignerBuilder.build();
        String signV1 = apkSigner.signV1();
        appendSignToFile(binV1, apk.getName(), signV1);


        if (signV2Enabled || signV3Enabled) {
            // sign version 1
            File outputApk = new File(TMP_DIR_PATH + File.separator + "out_" + apkName);


            apkSignerBuilder = new ApkSigner.Builder(signerConfigs, true)
                    .setInputApk(apk)
                    .setOutputApk(outputApk)
                    .setSignDigest(apk.getPath(), signV1);
            apkSigner = apkSignerBuilder.build();
            apkSigner.addSignV1ToApk();

            // generate v2 v3
            apkSignerBuilder =
                    new ApkSigner.Builder(new ArrayList<>(0), true)
                            .setInputApk(outputApk)
                            .setOtherSignersSignaturesPreserved(false)
                            .setV1SigningEnabled(true)
                            .setV2SigningEnabled(signV2Enabled)
                            .setV3SigningEnabled(signV3Enabled)
                            .setV4SigningEnabled(false)
                            .setForceSourceStampOverwrite(false)
                            .setVerityEnabled(false)
                            .setV4ErrorReportingEnabled(false)
                            .setDebuggableApkPermitted(debuggableApkPermitted)
                            .setSigningCertificateLineage(null);
            apkSigner = apkSignerBuilder.build();
            String digestV2V3 = apkSigner.getContentDigestsV2V3Cafebazaar();

            apkSignerBuilder =
                    new ApkSigner.Builder(signerConfigs)
                            .setSignDigest(outputApk.getPath(), digestV2V3)
                            .setOtherSignersSignaturesPreserved(false)
                            .setV1SigningEnabled(true)
                            .setV2SigningEnabled(signV2Enabled)
                            .setV3SigningEnabled(signV3Enabled)
                            .setV4SigningEnabled(false)
                            .setForceSourceStampOverwrite(false)
                            .setVerityEnabled(false)
                            .setV4ErrorReportingEnabled(false)
                            .setDebuggableApkPermitted(debuggableApkPermitted)
                            .setSigningCertificateLineage(null);
            if (minSdkVersionSpecified) {
                apkSignerBuilder.setMinSdkVersion(minSdkVersion);
            }
            apkSigner = apkSignerBuilder.build();

            String signV2V3 = apkSigner.signContentDigestsV2V3Cafebazaar();

            appendSignToFile(binV2V3, apk.getName(), signV2V3);
        }
    }

    private void appendSignToFile(File file, String apkName, String sign) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file, true), StandardCharsets.UTF_8));
        writer.println(apkName);
        writer.println(sign);
        writer.close();
    }

    private void generateFinalBinFile(File binV1, File binV2V3) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(bin, false), StandardCharsets.UTF_8));

        String implementationVersion = getClass().getPackage().getImplementationVersion();
        writer.println(String.format("version: %s;java_version: %s", implementationVersion,
                System.getProperty("java.specification.version")));
        writer.println("v2:" + signV2Enabled + ",v3:" + signV3Enabled);
        if (!signV2Enabled && !signV3Enabled) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(binV1), StandardCharsets.UTF_8));

            String line;
            int lineCounter = 0;
            String apkName;
            while ((line = reader.readLine()) != null) {

                if (lineCounter == 0) {
                    File apk = new File(line);
                    apkName = apk.getName();
                    writer.println(apkName);
                } else {
                    writer.println(line);
                }
                lineCounter = (lineCounter + 1) % 2;
            }

            reader.close();
            writer.close();
        } else {
            BufferedReader readerV1 = new BufferedReader(new InputStreamReader(new FileInputStream(binV1), StandardCharsets.UTF_8));
            BufferedReader readerV2V3 = new BufferedReader(new InputStreamReader(new FileInputStream(binV2V3), StandardCharsets.UTF_8));

            String lineV1;
            String lineV2V3;
            int lineCounter = 0;
            String apkName;

            while ((lineV1 = readerV1.readLine()) != null && (lineV2V3 = readerV2V3.readLine()) != null) {
                if (lineCounter == 0) {
                    File apk = new File(lineV1);
                    apkName = apk.getName();
                    writer.println(apkName);
                } else {
                    writer.println(lineV1);
                    writer.println(lineV2V3);
                }

                lineCounter = (lineCounter + 1) % 2;
            }

            readerV1.close();
            readerV2V3.close();
            writer.flush();
            writer.close();
        }
    }

}
