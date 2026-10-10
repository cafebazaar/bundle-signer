package ir.cafebazaar.bundlesigner;

import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.apksig.SigningCertificateLineage;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RotationOptionsTest {

    private static final String LINEAGE = "rsa-2048-lineage-2-signers";

    @Test
    public void singleSignerWithoutLineageIsAccepted() throws Exception {
        RotationOptions.validate(false, false, 1);
        RotationOptions.validate(true, false, 1);
    }

    @Test
    public void lineageWithV3AndTwoSignersIsAccepted() throws Exception {
        RotationOptions.validate(true, true, 2);
    }

    @Test
    public void lineageRequiresV3() {
        assertRejected(() -> RotationOptions.validate(false, true, 2),
                "--lineage requires --v3-signing-enabled true");
    }

    @Test
    public void lineageRequiresTwoSigners() {
        assertRejected(() -> RotationOptions.validate(true, true, 1),
                "--lineage requires at least two signers");
    }

    @Test
    public void multipleSignersRequireLineage() {
        assertRejected(() -> RotationOptions.validate(true, false, 2),
                "Multiple signers require --lineage");
    }

    @Test
    public void malformedLineageIsRejected() {
        String path = TestFixtures.resourcePath("ir/cafebazaar/apksig/rsa-2048-lineage-invalid-magic");
        assertRejected(() -> RotationOptions.loadLineage(path), "Failed to read lineage file");
    }

    @Test
    public void missingLineageFileIsRejected() {
        assertRejected(() -> RotationOptions.loadLineage("does-not-exist.lineage"),
                "Failed to read lineage file");
    }

    @Test
    public void validLineageLoads() throws Exception {
        String path = TestFixtures.resourcePath("ir/cafebazaar/apksig/" + LINEAGE);
        assertEquals(2, RotationOptions.loadLineage(path).size());
    }

    @Test
    public void signersInLineageAreAccepted() throws Exception {
        SigningCertificateLineage lineage = TestFixtures.lineage(LINEAGE);
        RotationOptions.checkSignersInLineage(lineage,
                Arrays.asList(TestFixtures.signer("rsa-2048"), TestFixtures.signer("rsa-2048_2")));
    }

    @Test
    public void signerNotInLineageIsRejected() throws Exception {
        SigningCertificateLineage lineage = TestFixtures.lineage(LINEAGE);
        ApkSigner.SignerConfig unrelated = TestFixtures.signer("rsa-2048_3");
        assertRejected(() -> RotationOptions.checkSignersInLineage(lineage,
                        Arrays.asList(TestFixtures.signer("rsa-2048"), unrelated)),
                "is not in the provided lineage");
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static void assertRejected(ThrowingAction action, String expectedMessage) {
        try {
            action.run();
            fail("Expected ParameterException containing: " + expectedMessage);
        } catch (ParameterException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(expectedMessage));
        } catch (Exception e) {
            fail("Expected ParameterException but got " + e);
        }
    }
}
