package ir.cafebazaar.bundlesigner.command;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.bundlesigner.TestFixtures;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GenBinCommandTest {

    private static final File OUT = new File("genBinCommandOutput");

    @Before
    public void setUp() {
        TestFixtures.deleteRecursively(OUT);
    }

    @After
    public void tearDown() {
        TestFixtures.deleteRecursively(OUT);
    }

    @Test
    public void preservesDotsInBundleName() throws Exception {
        Files.createDirectories(OUT.toPath());
        File bundle = new File(OUT, "app.release.v2.aab");
        Files.copy(new File(TestFixtures.BUNDLE).toPath(), bundle.toPath());
        new GenBinCommand.Builder()
                .setBundle(bundle.getPath())
                .setBin(OUT.getPath())
                .setSingerConfigs(Collections.singletonList(TestFixtures.signer("rsa-2048")))
                .setDebuggableApkPermitted(true)
                .build()
                .execute();

        assertTrue(new File(OUT, "app.release.v2.bin").isFile());
    }

    @Test
    public void builderStateAndTempFilesDoNotLeakBetweenRuns() throws Exception {
        ApkSigner.SignerConfig signer = TestFixtures.signer("rsa-2048");
        File first = TestFixtures.genBin(new File(OUT, "first"), true, true, signer);

        File secondDir = new File(OUT, "second");
        secondDir.mkdirs();
        new GenBinCommand.Builder()
                .setBundle(TestFixtures.BUNDLE)
                .setBin(secondDir.getPath())
                .setSignV2Enabled(true)
                .setSingerConfigs(Collections.singletonList(signer))
                .setDebuggableApkPermitted(true)
                .build()
                .execute();

        List<String> firstLines = Files.readAllLines(first.toPath(), StandardCharsets.UTF_8);
        List<String> secondLines =
                Files.readAllLines(new File(secondDir, "bundle.bin").toPath(), StandardCharsets.UTF_8);
        assertEquals("v2:true,v3:false", secondLines.get(1));
        assertEquals(firstLines.size(), secondLines.size());
    }
}
