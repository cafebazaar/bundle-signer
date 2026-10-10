package ir.cafebazaar.bundlesigner.command;

import ir.cafebazaar.apksig.ApkVerifier;
import ir.cafebazaar.apksig.SigningCertificateLineage;
import ir.cafebazaar.bundlesigner.TestFixtures;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RotationSigningTest {

    private static final File OUT = new File("rotationSigningOutput");
    private static final String LINEAGE = "rsa-2048-lineage-2-signers";
    private static X509Certificate oldCert;
    private static X509Certificate newCert;
    private static File rotatedApks;

    @BeforeClass
    public static void signRotatedBundle() throws Exception {
        TestFixtures.deleteRecursively(OUT);
        oldCert = TestFixtures.cert("rsa-2048");
        newCert = TestFixtures.cert("rsa-2048_2");
        File bin = TestFixtures.genBin(new File(OUT, "rotated-bin"), true, true,
                TestFixtures.lineage(LINEAGE),
                TestFixtures.signer("rsa-2048"), TestFixtures.signer("rsa-2048_2"));
        rotatedApks = TestFixtures.signBundle(bin, new File(OUT, "rotated-apks"));
    }

    @AfterClass
    public static void cleanUp() {
        TestFixtures.deleteRecursively(OUT);
    }

    @Test
    public void rotatedUniversalApkHasOldV1V2AndNewV3WithLineage() throws Exception {
        assertRotated(new File(rotatedApks, "universal.apk"), true);
    }

    @Test
    public void rotatedSplitApkHasOldV1V2AndNewV3WithLineage() throws Exception {
        assertRotated(new File(rotatedApks, "splits_base-master.apk"), true);
    }

    @Test
    public void rotationWithSignersInReverseOrder() throws Exception {
        File bin = TestFixtures.genBin(new File(OUT, "reverse-bin"), true, true,
                TestFixtures.lineage(LINEAGE),
                TestFixtures.signer("rsa-2048_2"), TestFixtures.signer("rsa-2048"));
        File apks = TestFixtures.signBundle(bin, new File(OUT, "reverse-apks"));
        assertRotated(new File(apks, "universal.apk"), true);
    }

    @Test
    public void rotationWithoutV2() throws Exception {
        File bin = TestFixtures.genBin(new File(OUT, "nov2-bin"), false, true,
                TestFixtures.lineage(LINEAGE),
                TestFixtures.signer("rsa-2048"), TestFixtures.signer("rsa-2048_2"));
        File apks = TestFixtures.signBundle(bin, new File(OUT, "nov2-apks"));
        assertRotated(new File(apks, "universal.apk"), false);
    }

    @Test
    public void singleSignerWithoutLineageIsUnchanged() throws Exception {
        File bin = TestFixtures.genBin(new File(OUT, "single-bin"), true, true,
                TestFixtures.signer("rsa-2048"));
        File apks = TestFixtures.signBundle(bin, new File(OUT, "single-apks"));

        ApkVerifier.Result result = TestFixtures.verify(new File(apks, "universal.apk"));
        assertTrue(result.getErrors().toString(), result.isVerified());
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertTrue(result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertEquals(oldCert, result.getV1SchemeSigners().get(0).getCertificate());
        assertEquals(oldCert, result.getV2SchemeSigners().get(0).getCertificate());
        assertEquals(oldCert, result.getV3SchemeSigners().get(0).getCertificate());
        assertNull(result.getSigningCertificateLineage());
    }

    @Test
    public void lineageWithoutOldSignerFailsLoudly() throws Exception {
        try {
            TestFixtures.genBin(new File(OUT, "missing-old-bin"), true, true,
                    TestFixtures.lineage(LINEAGE), TestFixtures.signer("rsa-2048_2"));
            fail("genbin must fail when the oldest lineage signer is missing");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().startsWith("Failed to generate v1 signature"));
        }
    }

    private static void assertRotated(File apk, boolean v2Expected) throws Exception {
        ApkVerifier.Result result = TestFixtures.verify(apk);
        assertTrue(result.getErrors().toString(), result.isVerified());
        assertTrue(result.isVerifiedUsingV1Scheme());
        assertEquals(v2Expected, result.isVerifiedUsingV2Scheme());
        assertTrue(result.isVerifiedUsingV3Scheme());
        assertEquals(oldCert, result.getV1SchemeSigners().get(0).getCertificate());
        if (v2Expected) {
            assertEquals(oldCert, result.getV2SchemeSigners().get(0).getCertificate());
        }
        assertEquals(newCert, result.getV3SchemeSigners().get(0).getCertificate());
        SigningCertificateLineage lineage = result.getSigningCertificateLineage();
        assertEquals(Arrays.asList(oldCert, newCert), lineage.getCertificatesInLineage());
    }
}
