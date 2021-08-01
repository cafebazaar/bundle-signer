package ir.cafebazaar.bundlesigner.command;

import ir.cafebazaar.bundlesigner.BundleSignerTool;
import ir.cafebazaar.bundlesigner.SignerParams;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import shadow.bundletool.com.android.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GenBinCommandTestCase {
    private static final String outputDir = "genBinCommandOutput";

    @Before
    public void setUp() {
        try {
            FileUtils.deleteRecursivelyIfExists(new File(outputDir));
        } catch (IOException e) {
            System.out.println("Failed to setup test.");
        }
    }

    @After
    public void tearDown() {
        try {
            FileUtils.deleteRecursivelyIfExists(new File(outputDir));
        } catch (IOException e) {
            System.out.println("Failed to clean up test.");
        }
    }

    @Test
    public void testExecuteGeneratesExpectedArtifacts() throws Exception {
        String bundleFileName = "bundle";

        String bundlePath = Objects.requireNonNull(getClass().getClassLoader().getResource(String.format("ir.cafebazaar.bundlesigner/%s.aab", bundleFileName))).getPath();

        GenBinCommand.Builder builder = new GenBinCommand.Builder();
        boolean v2Enabled = false;
        boolean v3Enabled = false;
        List<SignerParams> signers = new ArrayList<>(1);
        SignerParams signerParams = new SignerParams();
//        List<BundleSignerTool.ProviderInstallSpec> providers = new ArrayList<>();
//        BundleSignerTool.ProviderInstallSpec providerParams = new BundleSignerTool.ProviderInstallSpec();

        builder.setBundle(bundlePath)
                .setBin(outputDir)
                .setSignV2Enabled(v2Enabled)
                .setSignV3Enabled(v3Enabled)
                .setDebuggableApkPermitted(true)
                .setVerbose(true)
//                .setSingerConfigs()
                .setMinSdkVersion(1)
                .setMinSdkVersionSpecified(true);

        GenBinCommand command = builder.build();

        command.execute();

        assertTrue(new File(outputDir + File.separator + "universal.apk").exists());
        assertTrue(new File(outputDir + File.separator + String.format("%s.apks", bundleFileName)).exists());
        assertTrue(new File(outputDir + File.separator + "splits_base-master.apk").exists());
        assertFalse(new File(outputDir + File.separator + "universal.apks").exists());
    }
}
