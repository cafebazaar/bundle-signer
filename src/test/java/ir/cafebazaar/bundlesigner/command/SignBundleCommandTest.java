package ir.cafebazaar.bundlesigner.command;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import shadow.bundletool.com.android.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.Objects;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class SignBundleCommandTest {

    private static final String outputDir = "signCommandOutput";

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
        String binFilePath = Objects.requireNonNull(getClass().getClassLoader().getResource(String.format("ir.cafebazaar.bundlesigner/%s.bin", bundleFileName))).getPath();

        SignBundleCommand.Builder builder = new SignBundleCommand.Builder();
        builder.setBundle(bundlePath);
        builder.setBinFile(binFilePath);
        builder.setOutputPath(outputDir);
        SignBundleCommand command = builder.build();

        command.execute();

        assertTrue(new File(outputDir + File.separator + "universal.apk").exists());
        assertTrue(new File(outputDir + File.separator + String.format("%s.apks", bundleFileName)).exists());
        assertTrue(new File(outputDir + File.separator + "splits_base-master.apk").exists());
        assertFalse(new File(outputDir + File.separator + "universal.apks").exists());
    }
}