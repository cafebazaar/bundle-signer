package ir.cafebazaar.bundlesigner.command;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.apksig.apk.ApkFormatException;
import ir.cafebazaar.bundlesigner.BundleToolWrapper;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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

        public GenBinCommand.Builder setVerbose(boolean verbose){
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
        String apksPath = BundleToolWrapper.buildApkSet(bundle, TMP_DIR_PATH, false);
        String universalPath = BundleToolWrapper.buildApkSet(bundle, TMP_DIR_PATH, true);

        File binV1 = new File(TMP_DIR_PATH + File.separator + "binv1");
        File binV2V3 = new File(TMP_DIR_PATH + File.separator + "binv2_v3");
        File tmpBin = new File(TMP_DIR_PATH + File.separator + "tmp_bin");

        extractAndSignApkSet(apksPath, binV1, binV2V3, tmpBin);

        extractAndSignApkSet(universalPath, binV1, binV2V3, tmpBin);

        generateFinalBinFile(binV1, binV2V3);

        if (verbose) {
            System.out.println("Digest content generated");
        }

    }

    private void extractAndSignApkSet(String apksPath, File binV1, File binV2V3, File tmpBin) throws Exception {
        FileInputStream apksStream = new FileInputStream(apksPath);
        ZipInputStream zis = new ZipInputStream(apksStream);
        ZipEntry zipEntry = zis.getNextEntry();

        while (zipEntry != null) {
            if (!zipEntry.getName().contains(".apk")) {
                zipEntry = zis.getNextEntry();
                continue;
            }

            String fileName = zipEntry.getName();
            File apk = new File(TMP_DIR_PATH + File.separator + fileName);
            new File(apk.getParent()).mkdirs();

            FileOutputStream fos = new FileOutputStream(apk);
            int len;
            byte[] buffer = new byte[1024];
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();

            String apkName = zipEntry.getName().split(".apk")[0] + ".apk";
            apkName = apkName.replace("/", "_");

            calculateSignOfApk(apkName, binV1, binV2V3, tmpBin, apk);

            zis.closeEntry();
            zipEntry = zis.getNextEntry();
        }
        zis.closeEntry();
        zis.close();
        apksStream.close();
    }

    private void calculateSignOfApk(String apkName, File binV1, File binV2V3, File tmpBin, File apk) throws IOException,
            ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException {

        ApkSigner.Builder apkSignerBuilder =
                new ApkSigner.Builder(new ArrayList<>(0), true)
                        .setInputApk(apk)
                        .setOutputBin(tmpBin)
                        .setOtherSignersSignaturesPreserved(false)
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(signV2Enabled)
                        .setV3SigningEnabled(signV3Enabled)
                        .setDebuggableApkPermitted(debuggableApkPermitted);
        if (minSdkVersionSpecified) {
            apkSignerBuilder.setMinSdkVersion(minSdkVersion);
        }

        ApkSigner apkSigner = apkSignerBuilder.build();
        apkSigner.genV1Bin();

        apkSignerBuilder = new ApkSigner.Builder(signerConfigs)
                .setInputBin(tmpBin)
                .setOutputBin(tmpBin);

        apkSigner = apkSignerBuilder.build();
        apkSigner.signV1();
        appendFiles(tmpBin, binV1);

        if (signV2Enabled || signV2Enabled) {
            // sign version 1
            File outputApk = new File(TMP_DIR_PATH + File.separator + "out_" + apkName);

            apkSignerBuilder = new ApkSigner.Builder(signerConfigs, true)
                    .setInputApk(apk)
                    .setOutputApk(outputApk)
                    .setInputBin(tmpBin);
            apkSigner = apkSignerBuilder.build();
            apkSigner.addSignV1ToApk();

            // generate v2 v3
            apkSignerBuilder =
                    new ApkSigner.Builder(new ArrayList<>(0), true)
                            .setInputApk(outputApk)
                            .setOutputBin(tmpBin)
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
            apkSigner.getContentDigestsV2V3Cafebazaar();

            apkSignerBuilder =
                    new ApkSigner.Builder(signerConfigs)
                            .setInputBin(tmpBin)
                            .setOutputBin(tmpBin)
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

            apkSigner.signContentDigestsV2V3Cafebazaar();

            appendFiles(tmpBin, binV2V3);
        }
    }

    private static void appendFiles(File src, File dest) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(src));
        PrintWriter writer = new PrintWriter(new FileWriter(dest, true));

        String line;
        while ((line = reader.readLine()) != null) {
            writer.println(line);
        }

        reader.close();
        writer.close();

    }

    private void generateFinalBinFile(File binV1, File binV2V3) throws IOException {
        PrintWriter writer = new PrintWriter(new FileWriter(bin));
        writer.println("version: 0.1.4");
        writer.println("v2:" + signV2Enabled + ",v3:" + signV3Enabled);
        if (!signV2Enabled && !signV3Enabled) {
            BufferedReader reader = new BufferedReader(new FileReader(binV1));

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
            BufferedReader readerV1 = new BufferedReader(new FileReader(binV1));
            BufferedReader readerV2V3 = new BufferedReader(new FileReader(binV2V3));

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
            writer.close();
        }
    }

}
