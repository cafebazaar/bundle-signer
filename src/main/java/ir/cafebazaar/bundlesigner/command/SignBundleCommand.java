package ir.cafebazaar.bundlesigner.command;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.bundlesigner.BundleToolWrapper;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.FileHeader;
import org.apache.log4j.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ir.cafebazaar.bundlesigner.BundleSignerTool.TMP_DIR_PATH;

public class SignBundleCommand {

    private final File bundle;
    private final File binFile;
    private final String outputPath;

    private Map<String, String> apkSignV1;
    private Map<String, String> apkSignV2V3;

    private boolean signV2Enabled;
    private boolean signV3Enabled;

    private static final Logger logger = Logger.getLogger(String.valueOf(SignBundleCommand.class));

    private SignBundleCommand(File bundle, File binFile, String outputPath) {
        this.bundle = bundle;
        this.binFile = binFile;
        this.outputPath = outputPath;
    }

    public static class Builder {

        private static File bundle;
        private static File binFile;
        private static String outputPath;

        public Builder setBundle(String bundlePath) {
            bundle = new File(bundlePath);
            return this;
        }

        public Builder setBinFile(String binFilePath) {
            binFile = new File(binFilePath);
            return this;
        }

        public Builder setOutputPath(String outputPath) {
            Builder.outputPath = outputPath;
            return this;
        }

        public SignBundleCommand build() throws IOException {

            if (bundle == null || binFile == null || outputPath == null)
                return null;

            return new SignBundleCommand(bundle, binFile, outputPath);
        }
    }

    private void processBinFile() throws IOException {
        BufferedReader binReader = new BufferedReader(new InputStreamReader(new FileInputStream(binFile), StandardCharsets.UTF_8));
        binReader.readLine(); // skip bundle signer version line
        String line = binReader.readLine();

        String[] signVersionInfo = line.split(","); // Example: v2:true,v3:false
        signV2Enabled = signVersionInfo[0].split(":")[1].trim().equals("true");
        signV3Enabled = signVersionInfo[0].split(":")[1].trim().equals("true");

        apkSignV1 = new HashMap<>();
        apkSignV2V3 = new HashMap<>();

        String apkName = null;
        int expectedSignVersion = 1;

        while ((line = binReader.readLine()) != null) {
            if (line.contains(".apk")) {
                apkName = line;
            } else if (expectedSignVersion == 1) {

                apkSignV1.put(apkName, line);
                if (signV2Enabled || signV3Enabled)
                    expectedSignVersion = 2;

            } else {
                apkSignV2V3.put(apkName, line);
                expectedSignVersion = 1;
            }
        }

        logger.info("processed sign file.");
    }

    public void execute() throws Exception {
        logger.info("Started sign command.");
        processBinFile();
        String apksPath = BundleToolWrapper.buildApkSet(bundle, outputPath, false);
        String universalPath = BundleToolWrapper.buildApkSet(bundle, TMP_DIR_PATH, true);

        extractAndSignApks(apksPath);
        extractAndSignApks(universalPath);
    }

    private void extractAndSignApks(String apksPath) throws Exception {
        ZipFile apkZip = new ZipFile(apksPath);
        apkZip.extractAll(TMP_DIR_PATH);
        List<FileHeader> apkSetEntries = apkZip.getFileHeaders();

        for (FileHeader apkSetEntry : apkSetEntries) {
            if(! apkSetEntry.getFileName().contains("apk"))
                continue;

            String apkName;
            String apkType = null;
            if (apkSetEntry.getFileName().contains("/"))
            {
                String[] apkNameParts = apkSetEntry.getFileName().split("/");
                apkType = apkNameParts[0];
                apkName = apkNameParts[1];
            }
            else{
                apkName = "universal.apk";
            }


            File v1SignedApk;
            if (signV2Enabled || signV3Enabled) {
                v1SignedApk = new File(TMP_DIR_PATH + File.separator + "v1_" + apkName);
            } else {
                if (apkType != null) {
                    v1SignedApk = new File(outputPath + File.separator + apkType + "_" + apkName);
                }
                else
                {
                    v1SignedApk = new File(outputPath + File.separator + apkName);
                }
            }

            File apk = new File(TMP_DIR_PATH + File.separator + apkSetEntry.getFileName());
            List<ApkSigner.SignerConfig> signerConfigs = new ArrayList<>(0);

            String apkDigest;
            try{
                apkDigest = apkSignV1.get(apkName);
            }
            catch (Exception e){
                String msg = String.format("Digest of %s not found in bin file.", apkName);
                throw new SignBundleException(msg);
            }

            ApkSigner.Builder apkSignerBuilder =
                    new ApkSigner.Builder(signerConfigs, true)
                            .setInputApk(apk)
                            .setOutputApk(v1SignedApk)
                            .setSignDigest(apk.getPath(), apkDigest);
            apkSignV1.remove(apkName);

            ApkSigner apkSigner = apkSignerBuilder.build();
            apkSigner.addSignV1ToApk();

            if (signV2Enabled || signV3Enabled) {

                File V2V3SignedApk;
                if (apkType != null) {
                    V2V3SignedApk = new File(outputPath + File.separator + apkType + "_" + apkName);
                }
                else
                {
                    V2V3SignedApk = new File(outputPath + File.separator + apkName);
                }

                String apkDigestV2V3;
                try{
                    apkDigestV2V3 = apkSignV2V3.get(apkName);
                } catch (Exception e){
                    String msg = String.format("Digest of %s not found in bin file.", apkName);
                    throw new SignBundleException(msg);
                }

                apkSignerBuilder =
                        new ApkSigner.Builder(new ArrayList<>(0), true)
                                .setInputApk(v1SignedApk)
                                .setOutputApk(V2V3SignedApk)
                                .setSignDigest(v1SignedApk.getPath(), apkDigestV2V3)
                                .setOtherSignersSignaturesPreserved(false)
                                .setV1SigningEnabled(false)
                                .setV2SigningEnabled(signV2Enabled)
                                .setV3SigningEnabled(signV3Enabled)
                                .setV4SigningEnabled(false)
                                .setForceSourceStampOverwrite(false)
                                .setVerityEnabled(false)
                                .setV4ErrorReportingEnabled(false)
                                .setDebuggableApkPermitted(true)
                                .setSigningCertificateLineage(null);

                apkSignV2V3.remove(apkName);
                apkSigner = apkSignerBuilder.build();

                apkSigner.addSignedContentDigestsV2V3Cafebazaar();

            }
        }

        logger.info(String.format("Signed %s", apksPath));
    }
}