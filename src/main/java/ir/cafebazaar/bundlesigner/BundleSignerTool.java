/*
 *
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modifications Copyright (C) 2021 Cafe Bazaar
 */

package ir.cafebazaar.bundlesigner;

import com.android.tools.build.bundletool.model.exceptions.InvalidBundleException;
import ir.cafebazaar.apksig.ApkSigner;
import ir.cafebazaar.apksig.ApkVerifier;
import ir.cafebazaar.apksig.apk.ApkFormatException;
import ir.cafebazaar.apksig.apk.MinSdkVersionException;
import ir.cafebazaar.bundlesigner.command.GenBinCommand;
import ir.cafebazaar.bundlesigner.command.SignBundleCommand;
import org.apache.log4j.Logger;
import org.conscrypt.OpenSSLProvider;
import shadow.bundletool.com.android.utils.FileUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.*;


/**
 * Command-line tool for signing bundles and for checking whether an APK's signature are expected to
 * verify on Android devices.
 */
public class BundleSignerTool {

    private static final String VERSION = BundleSignerTool.class.getPackage().getImplementationVersion();
    private static final String HELP_PAGE_GENERAL = "/help.txt";
    private static final String HELP_PAGE_GET_CONTENT_DIGESTS = "/help_get_content_digests.txt";
    private static final String HELP_PAGE_SIGN_BUNDLE = "/help_sign_bundle.txt";
    private static final String HELP_PAGE_VERIFY = "/help_verify.txt";

    public static String TMP_DIR_PATH;
    private static boolean keepTmp = false;
    private static final Logger logger = Logger.getLogger(String.valueOf(BundleSignerTool.class));


    private static MessageDigest sha256 = null;
    private static MessageDigest sha1 = null;
    private static MessageDigest md5 = null;


    static {
        Locale.setDefault(new Locale("en"));
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        logger.info(String.format("Set up project, java version: %s, vendor: %s, vm: %s, jre: %s, f-memory: %s," +
                        " m-memory: %s",
                System.getProperty("java.version"),
                System.getProperty("java.vendor"),
                System.getProperty("java.vm.name"),
                System.getProperty("java.runtime.name"),
                Runtime.getRuntime().freeMemory(),
                Runtime.getRuntime().maxMemory()));
        try {
            Path tmpDirectory = Files.createTempDirectory("bundle_signer");
            TMP_DIR_PATH = tmpDirectory.toAbsolutePath().toString();
            Runtime.getRuntime().addShutdownHook(
                    new Thread(() -> {
                        try {
                            if(keepTmp){
                                logger.info("Process finished, tmp is kept.");
                                System.exit(0);
                            }
                            FileUtils.deleteRecursivelyIfExists(tmpDirectory.toFile());
                            logger.info("Process finished.");

                        } catch (Exception e) {
                            System.out.println("Warning: Process Interrupted.");
                            logger.info(e.getStackTrace());
                            System.exit(8);
                        }
                    }));
        } catch (Exception e) {
            System.err.println(e.getMessage());
            logger.info(e.getStackTrace());
            System.exit(1);
        }
    }

    public static void main(String[] params) throws Exception {
        if ((params.length == 0) || ("--help".equals(params[0])) || ("-h".equals(params[0]))) {
            printUsage(HELP_PAGE_GENERAL);
            return;
        } else if ("--version".equals(params[0])) {
            System.out.println(VERSION);
            return;
        }

        addProviders();

        int exitCode = 0;
        String exitMessage = "";

        String cmd = params[0];
        try {
            switch (cmd) {
                case "genbin":
                    getContentDigest(Arrays.copyOfRange(params, 1, params.length));
                    break;
                case "signbundle":
                    signBundle(Arrays.copyOfRange(params, 1, params.length));
                    break;
                case "verify":
                    verify(Arrays.copyOfRange(params, 1, params.length));
                    break;
                case "help":
                    printUsage(HELP_PAGE_GENERAL);
                    break;
                case "version":
                    System.out.println(VERSION);
                    break;
                default:
                    throw new ParameterException(
                            "Unsupported command: " + cmd + ". See --help for supported commands");
            }
        } catch (ParameterException | OptionsParser.OptionsException e) {
            exitMessage = Arrays.toString(e.getStackTrace());
            exitCode = 2;
        } catch (MinSdkVersionException e) {
            exitMessage = "Failed to determine APK's minimum supported platform version"
                    + ". Use --min-sdk-version to override";
            exitCode = 3;
        } catch (InvalidBundleException e) {
            exitMessage = Arrays.toString(e.getStackTrace());
            exitCode = 5;
        } catch (BundleToolIOException e) {
            exitMessage = Arrays.toString(e.getStackTrace());
            exitCode = 6;

        } catch (ApkFormatException e) {
            exitMessage = Arrays.toString(e.getStackTrace());
            exitCode = 7;

        } catch (RuntimeException e) {
            exitMessage = Arrays.toString(e.getStackTrace());
            exitCode = 4;
        } finally {
            if (!exitMessage.isEmpty())
                System.err.println(exitMessage);
                logger.info(exitMessage);
            System.exit(exitCode);
        }
    }

    /**
     * Adds additional security providers to add support for signature algorithms not covered by
     * the default providers.
     */
    private static void addProviders() {
        try {
            Security.addProvider(new OpenSSLProvider());
        } catch (UnsatisfiedLinkError e) {
            // This is expected if the library path does not include the native conscrypt library;
            // the default providers support all but PSS algorithms.
        }
    }

    private static void getContentDigest(String[] params) throws Exception {

        if (params.length == 0) {
            printUsage(HELP_PAGE_GET_CONTENT_DIGESTS);
            return;
        }

        String binFilePath = null;
        String bundlePath = null;
        boolean verbose = false;
        boolean v2SigningEnabled = false;
        boolean v3SigningEnabled = false;
        boolean debuggableApkPermitted = true;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;

        List<SignerParams> signers = new ArrayList<>(1);
        SignerParams signerParams = new SignerParams();
        List<ProviderInstallSpec> providers = new ArrayList<>();
        ProviderInstallSpec providerParams = new ProviderInstallSpec();
        OptionsParser optionsParser = new OptionsParser(params);

        String optionName;
        String optionOriginalForm;
        while ((optionName = optionsParser.nextOption()) != null) {
            optionOriginalForm = optionsParser.getOptionOriginalForm();
            switch (optionName) {
                case "help":
                case "h":
                    printUsage(HELP_PAGE_GET_CONTENT_DIGESTS);
                    return;
                case "bin":
                    binFilePath = optionsParser.getRequiredValue("Output file path");
                    break;
                case "bundle":
                    bundlePath = optionsParser.getRequiredValue("Input file name");
                    break;
                case "min-sdk-version":
                    minSdkVersion = optionsParser.getRequiredIntValue("Minimum API Level");
                    minSdkVersionSpecified = true;
                    break;
                case "max-sdk-version":
                    maxSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
                    break;
                case "v2-signing-enabled":
                    v2SigningEnabled = optionsParser.getOptionalBooleanValue(true);
                    break;
                case "v3-signing-enabled":
                    v3SigningEnabled = optionsParser.getOptionalBooleanValue(true);
                    break;
                case "debuggable-apk-permitted":
                    debuggableApkPermitted = optionsParser.getOptionalBooleanValue(true);
                    break;
                case "v":
                case "verbose":
                    verbose = optionsParser.getOptionalBooleanValue(true);
                    break;
                case "keep-tmp":
                    keepTmp = optionsParser.getOptionalBooleanValue(true);
                    break;
                case "ks":
                    signerParams.setKeystoreFile(optionsParser.getRequiredValue("KeyStore file"));
                    break;
                case "ks-key-alias":
                    signerParams.setKeystoreKeyAlias(
                            optionsParser.getRequiredValue("KeyStore key alias"));
                    break;
                case "ks-pass":
                    signerParams.setKeystorePasswordSpec(
                            optionsParser.getRequiredValue("KeyStore password"));
                    break;
                case "key-pass":
                    signerParams.setKeyPasswordSpec(optionsParser.getRequiredValue("Key password"));
                    break;
                case "pass-encoding":
                    String charsetName =
                            optionsParser.getRequiredValue("Password character encoding");
                    try {
                        signerParams.setPasswordCharset(
                                PasswordRetriever.getCharsetByName(charsetName));
                    } catch (IllegalArgumentException e) {
                        throw new ParameterException(
                                "Unsupported password character encoding requested using"
                                        + " --pass-encoding: " + charsetName);
                    }
                    break;
                case "v1-signer-name":
                    signerParams.setV1SigFileBasename(
                            optionsParser.getRequiredValue("JAR signature file basename"));
                    break;
                case "ks-type":
                    signerParams.setKeystoreType(optionsParser.getRequiredValue("KeyStore type"));
                    break;
                case "ks-provider-name":
                    signerParams.setKeystoreProviderName(
                            optionsParser.getRequiredValue("JCA KeyStore Provider name"));
                    break;
                case "ks-provider-class":
                    signerParams.setKeystoreProviderClass(
                            optionsParser.getRequiredValue("JCA KeyStore Provider class name"));
                    break;
                case "ks-provider-arg":
                    signerParams.setKeystoreProviderArg(
                            optionsParser.getRequiredValue(
                                    "JCA KeyStore Provider constructor argument"));
                    break;
                case "key":
                    signerParams.setKeyFile(optionsParser.getRequiredValue("Private key file"));
                    break;
                case "cert":
                    signerParams.setCertFile(optionsParser.getRequiredValue("Certificate file"));
                    break;
                default:
                    throw new ParameterException(
                            "Unsupported option: " + optionOriginalForm + ". See --help for supported"
                                    + " options.");
            }
        }

        if (bundlePath == null) {
            throw new ParameterException("Missing input Bundle file path");
        }

        if (binFilePath == null) {
            throw new ParameterException("Missing output Bin file path");
        }

        if (!Files.exists(new File(binFilePath).toPath())) {
            throw new ParameterException("Input bundle file does not exist");
        }

        if (!signerParams.isEmpty()) {
            signers.add(signerParams);
        }

        if (!providerParams.isEmpty()) {
            providers.add(providerParams);
        }

        if (signers.isEmpty()) {
            throw new ParameterException("At least one signer must be specified");
        }

        if ((minSdkVersionSpecified) && (minSdkVersion > maxSdkVersion)) {
            throw new ParameterException(
                    "Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion + ")");
        }

        // Install additional JCA Providers
        for (ProviderInstallSpec providerInstallSpec : providers) {
            providerInstallSpec.installProvider();
        }

        List<ApkSigner.SignerConfig> signerConfigs = new ArrayList<>(signers.size());
        int signerNumber = 0;

        try (PasswordRetriever passwordRetriever = new PasswordRetriever()) {
            for (SignerParams signer : signers) {
                signerNumber++;
                signer.setName("signer #" + signerNumber);
                ApkSigner.SignerConfig signerConfig = getSignerConfig(signer, passwordRetriever);
                if (signerConfig == null) {
                    return;
                }
                signerConfigs.add(signerConfig);
            }
        }

        GenBinCommand.Builder commandBuilder = new GenBinCommand.Builder();
        commandBuilder.setBundle(bundlePath)
                .setBin(binFilePath)
                .setSignV2Enabled(v2SigningEnabled)
                .setSignV3Enabled(v3SigningEnabled)
                .setSingerConfigs(signerConfigs)
                .setVerbose(verbose)
                .setMinSdkVersionSpecified(minSdkVersionSpecified)
                .setMinSdkVersion(minSdkVersion)
                .setDebuggableApkPermitted(debuggableApkPermitted);

        GenBinCommand command = commandBuilder.build();
        command.execute();

    }

    private static void signBundle(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage(HELP_PAGE_SIGN_BUNDLE);
            return;
        }

        String bundlePath = null;
        String binFilePath = null;
        String outputPath = null;

        OptionsParser optionsParser = new OptionsParser(params);
        String optionName;
        while ((optionName = optionsParser.nextOption()) != null) {

            switch (optionName) {
                case "help":
                case "h":
                    printUsage(HELP_PAGE_SIGN_BUNDLE);
                    return;
                case "bundle":
                    bundlePath = optionsParser.getRequiredValue("Path to bundlePath file");
                    break;
                case "bin":
                    binFilePath = optionsParser.getRequiredValue("Path to bin file");
                    break;
                case "keep-tmp":
                    keepTmp = optionsParser.getOptionalBooleanValue(true);
                    break;
                case "out":
                    outputPath = optionsParser.getRequiredValue("Output files path");
                    break;
            }
        }

        if (bundlePath == null) {
            throw new ParameterException("Missing bundlePath file");
        }

        if (binFilePath == null) {
            throw new ParameterException("Missing bin file");
        }

        if (outputPath == null) {
            throw new ParameterException("Missing output path");
        }

        if (!Files.exists(Paths.get(binFilePath))) {
            throw new ParameterException("Passed Bin file does not exist");
        }

        if (!Files.exists(Paths.get(bundlePath))) {
            throw new ParameterException("Bundle file does not exist");
        }

        SignBundleCommand.Builder commandBuilder = new SignBundleCommand.Builder()
                .setBundle(bundlePath)
                .setBinFile(binFilePath)
                .setOutputPath(outputPath);

        SignBundleCommand command = commandBuilder.build();
        command.execute();

    }

    private static ApkSigner.SignerConfig getSignerConfig(
            SignerParams signer, PasswordRetriever passwordRetriever) {
        try {
            signer.loadPrivateKeyAndCerts(passwordRetriever);
        } catch (ParameterException e) {
            System.err.println(
                    "Failed to load signer \"" + signer.getName() + "\": " + e.getMessage());
            System.exit(2);
            return null;
        } catch (Exception e) {
            System.err.println("Failed to load signer \"" + signer.getName() + "\"");
            e.printStackTrace();
            System.exit(2);
            return null;
        }
        String v1SigBasename;
        if (signer.getV1SigFileBasename() != null) {
            v1SigBasename = signer.getV1SigFileBasename();
        } else if (signer.getKeystoreKeyAlias() != null) {
            v1SigBasename = signer.getKeystoreKeyAlias();
        } else if (signer.getKeyFile() != null) {
            String keyFileName = new File(signer.getKeyFile()).getName();
            int delimiterIndex = keyFileName.indexOf('.');
            if (delimiterIndex == -1) {
                v1SigBasename = keyFileName;
            } else {
                v1SigBasename = keyFileName.substring(0, delimiterIndex);
            }
        } else {
            throw new RuntimeException("Neither KeyStore key alias nor private key file available");
        }
        ApkSigner.SignerConfig signerConfig =
                new ApkSigner.SignerConfig.Builder(
                        v1SigBasename, signer.getPrivateKey(), signer.getCerts())
                        .build();
        return signerConfig;
    }

    private static void verify(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage(HELP_PAGE_VERIFY);
            return;
        }

        File inputApk = null;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;
        boolean maxSdkVersionSpecified = false;
        boolean printCerts = false;
        boolean verbose = false;
        boolean warningsTreatedAsErrors = false;
        boolean verifySourceStamp = false;
        File v4SignatureFile = null;
        OptionsParser optionsParser = new OptionsParser(params);
        String optionName;
        String optionOriginalForm = null;
        String sourceCertDigest = null;
        while ((optionName = optionsParser.nextOption()) != null) {
            optionOriginalForm = optionsParser.getOptionOriginalForm();
            if ("min-sdk-version".equals(optionName)) {
                minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
                minSdkVersionSpecified = true;
            } else if ("max-sdk-version".equals(optionName)) {
                maxSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
                maxSdkVersionSpecified = true;
            } else if ("print-certs".equals(optionName)) {
                printCerts = optionsParser.getOptionalBooleanValue(true);
            } else if (("v".equals(optionName)) || ("verbose".equals(optionName))) {
                verbose = optionsParser.getOptionalBooleanValue(true);
            } else if ("Werr".equals(optionName)) {
                warningsTreatedAsErrors = optionsParser.getOptionalBooleanValue(true);
            } else if (("help".equals(optionName)) || ("h".equals(optionName))) {
                printUsage(HELP_PAGE_VERIFY);
                return;
            } else if ("v4-signature-file".equals(optionName)) {
                v4SignatureFile = new File(optionsParser.getRequiredValue(
                        "Input V4 Signature File"));
            } else if ("in".equals(optionName)) {
                inputApk = new File(optionsParser.getRequiredValue("Input APK file"));
            } else if ("verify-source-stamp".equals(optionName)) {
                verifySourceStamp = optionsParser.getOptionalBooleanValue(true);
            } else if ("stamp-cert-digest".equals(optionName)) {
                sourceCertDigest = optionsParser.getRequiredValue(
                        "Expected source stamp certificate digest");
            } else {
                throw new ParameterException(
                        "Unsupported option: " + optionOriginalForm + ". See --help for supported"
                                + " options.");
            }
        }
        params = optionsParser.getRemainingParams();

        if (inputApk != null) {
            // Input APK has been specified in preceding parameters. We don't expect any more
            // parameters.
            if (params.length > 0) {
                throw new ParameterException(
                        "Unexpected parameter(s) after " + optionOriginalForm + ": " + params[0]);
            }
        } else {
            // Input APK has not been specified in preceding parameters. The next parameter is
            // supposed to be the input APK.
            if (params.length < 1) {
                throw new ParameterException("Missing APK");
            } else if (params.length > 1) {
                throw new ParameterException(
                        "Unexpected parameter(s) after APK (" + params[1] + ")");
            }
            inputApk = new File(params[0]);
        }

        if ((minSdkVersionSpecified) && (maxSdkVersionSpecified)
                && (minSdkVersion > maxSdkVersion)) {
            throw new ParameterException(
                    "Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion
                            + ")");
        }

        ApkVerifier.Builder apkVerifierBuilder = new ApkVerifier.Builder(inputApk);
        if (minSdkVersionSpecified) {
            apkVerifierBuilder.setMinCheckedPlatformVersion(minSdkVersion);
        }
        if (maxSdkVersionSpecified) {
            apkVerifierBuilder.setMaxCheckedPlatformVersion(maxSdkVersion);
        }
        if (v4SignatureFile != null) {
            if (!v4SignatureFile.exists()) {
                throw new ParameterException("V4 signature file does not exist: "
                        + v4SignatureFile.getCanonicalPath());
            }
            apkVerifierBuilder.setV4SignatureFile(v4SignatureFile);
        }

        ApkVerifier apkVerifier = apkVerifierBuilder.build();
        ApkVerifier.Result result;
        try {
            result = verifySourceStamp
                    ? apkVerifier.verifySourceStamp(sourceCertDigest)
                    : apkVerifier.verify();
        } catch (MinSdkVersionException e) {
            String msg = e.getMessage();
            if (!msg.endsWith(".")) {
                msg += '.';
            }
            throw new MinSdkVersionException(
                    "Failed to determine APK's minimum supported platform version"
                            + ". Use --min-sdk-version to override",
                    e);
        }

        boolean verified = result.isVerified();
        ApkVerifier.Result.SourceStampInfo sourceStampInfo = result.getSourceStampInfo();
        boolean warningsEncountered = false;
        if (verified) {
            List<X509Certificate> signerCerts = result.getSignerCertificates();
            if (verbose) {
                System.out.println("Verifies");
                System.out.println(
                        "Verified using v1 scheme (JAR signing): "
                                + result.isVerifiedUsingV1Scheme());
                System.out.println(
                        "Verified using v2 scheme (APK Signature Scheme v2): "
                                + result.isVerifiedUsingV2Scheme());
                System.out.println(
                        "Verified using v3 scheme (APK Signature Scheme v3): "
                                + result.isVerifiedUsingV3Scheme());
                System.out.println(
                        "Verified using v4 scheme (APK Signature Scheme v4): "
                                + result.isVerifiedUsingV4Scheme());
                System.out.println("Verified for SourceStamp: " + result.isSourceStampVerified());
                if (!verifySourceStamp) {
                    System.out.println("Number of signers: " + signerCerts.size());
                }
            }
            if (printCerts) {
                int signerNumber = 0;
                for (X509Certificate signerCert : signerCerts) {
                    signerNumber++;
                    printCertificate(signerCert, "Signer #" + signerNumber, verbose);
                }
                if (sourceStampInfo != null) {
                    printCertificate(sourceStampInfo.getCertificate(), "Source Stamp Signer",
                            verbose);
                }
            }
        } else {
            System.err.println("DOES NOT VERIFY");
        }

        for (ApkVerifier.IssueWithParams error : result.getErrors()) {
            System.err.println("ERROR: " + error);
        }

        @SuppressWarnings("resource") // false positive -- this resource is not opened here
        PrintStream warningsOut = warningsTreatedAsErrors ? System.err : System.out;
        for (ApkVerifier.IssueWithParams warning : result.getWarnings()) {
            warningsEncountered = true;
            warningsOut.println("WARNING: " + warning);
        }
        for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
            String signerName = signer.getName();
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println("ERROR: JAR signer " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println("WARNING: JAR signer " + signerName + ": " + warning);
            }
        }
        for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println(
                        "ERROR: APK Signature Scheme v2 " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println(
                        "WARNING: APK Signature Scheme v2 " + signerName + ": " + warning);
            }
        }
        for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) {
            String signerName = "signer #" + (signer.getIndex() + 1);
            for (ApkVerifier.IssueWithParams error : signer.getErrors()) {
                System.err.println(
                        "ERROR: APK Signature Scheme v3 " + signerName + ": " + error);
            }
            for (ApkVerifier.IssueWithParams warning : signer.getWarnings()) {
                warningsEncountered = true;
                warningsOut.println(
                        "WARNING: APK Signature Scheme v3 " + signerName + ": " + warning);
            }
        }

        if (sourceStampInfo != null) {
            for (ApkVerifier.IssueWithParams error : sourceStampInfo.getErrors()) {
                System.err.println("ERROR: SourceStamp: " + error);
            }
            for (ApkVerifier.IssueWithParams warning : sourceStampInfo.getWarnings()) {
                warningsOut.println("WARNING: SourceStamp: " + warning);
            }
        }

        if (!verified) {
            System.exit(1);
            return;
        }
        if ((warningsTreatedAsErrors) && (warningsEncountered)) {
            System.exit(1);
            return;
        }
    }

    private static void printUsage(String page) {
        try (BufferedReader in =
                     new BufferedReader(
                             new InputStreamReader(
                                     BundleSignerTool.class.getResourceAsStream(page),
                                     StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + page + " resource");
        }
    }

    /**
     * Prints details from the provided certificate to stdout.
     *
     * @param cert    the certificate to be displayed.
     * @param name    the name to be used to identify the certificate.
     * @param verbose boolean indicating whether public key details from the certificate should be
     *                displayed.
     * @throws NoSuchAlgorithmException     if an instance of MD5, SHA-1, or SHA-256 cannot be
     *                                      obtained.
     * @throws CertificateEncodingException if an error is encountered when encoding the
     *                                      certificate.
     */
    public static void printCertificate(X509Certificate cert, String name, boolean verbose)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        if (cert == null) {
            throw new NullPointerException("cert == null");
        }
        if (sha256 == null || sha1 == null || md5 == null) {
            sha256 = MessageDigest.getInstance("SHA-256");
            sha1 = MessageDigest.getInstance("SHA-1");
            md5 = MessageDigest.getInstance("MD5");
        }
        System.out.println(name + " certificate DN: " + cert.getSubjectDN());
        byte[] encodedCert = cert.getEncoded();
        System.out.println(name + " certificate SHA-256 digest: " + HexEncoding.encode(
                sha256.digest(encodedCert)));
        System.out.println(name + " certificate SHA-1 digest: " + HexEncoding.encode(
                sha1.digest(encodedCert)));
        System.out.println(
                name + " certificate MD5 digest: " + HexEncoding.encode(md5.digest(encodedCert)));
        if (verbose) {
            PublicKey publicKey = cert.getPublicKey();
            System.out.println(name + " key algorithm: " + publicKey.getAlgorithm());
            int keySize = -1;
            if (publicKey instanceof RSAKey) {
                keySize = ((RSAKey) publicKey).getModulus().bitLength();
            } else if (publicKey instanceof ECKey) {
                keySize = ((ECKey) publicKey).getParams()
                        .getOrder().bitLength();
            } else if (publicKey instanceof DSAKey) {
                // DSA parameters may be inherited from the certificate. We
                // don't handle this case at the moment.
                DSAParams dsaParams = ((DSAKey) publicKey).getParams();
                if (dsaParams != null) {
                    keySize = dsaParams.getP().bitLength();
                }
            }
            System.out.println(
                    name + " key size (bits): " + ((keySize != -1) ? String.valueOf(keySize)
                            : "n/a"));
            byte[] encodedKey = publicKey.getEncoded();
            System.out.println(name + " public key SHA-256 digest: " + HexEncoding.encode(
                    sha256.digest(encodedKey)));
            System.out.println(name + " public key SHA-1 digest: " + HexEncoding.encode(
                    sha1.digest(encodedKey)));
            System.out.println(
                    name + " public key MD5 digest: " + HexEncoding.encode(md5.digest(encodedKey)));
        }
    }

    private static class ProviderInstallSpec {
        String className;
        String constructorParam;
        Integer position;

        private boolean isEmpty() {
            return (className == null) && (constructorParam == null) && (position == null);
        }

        private void installProvider() throws Exception {
            if (className == null) {
                throw new ParameterException(
                        "JCA Provider class name (--provider-class) must be specified");
            }

            Class<?> providerClass = Class.forName(className);
            if (!Provider.class.isAssignableFrom(providerClass)) {
                throw new ParameterException(
                        "JCA Provider class " + providerClass + " not subclass of "
                                + Provider.class.getName());
            }
            Provider provider;
            if (constructorParam != null) {
                try {
                    // Single-arg Provider constructor
                    provider =
                            (Provider) providerClass.getConstructor(String.class)
                                    .newInstance(constructorParam);
                } catch (NoSuchMethodException e) {
                    // Starting from JDK 9 the single-arg constructor accepting the configuration
                    // has been replaced by a configure(String) method to be invoked after
                    // instantiating the Provider with the no-arg constructor.
                    provider = (Provider) providerClass.getConstructor().newInstance();
                    provider = (Provider) providerClass.getMethod("configure", String.class)
                            .invoke(provider, constructorParam);
                }
            } else {
                // No-arg Provider constructor
                provider = (Provider) providerClass.getConstructor().newInstance();
            }

            if (position == null) {
                Security.addProvider(provider);
            } else {
                Security.insertProviderAt(provider, position);
            }
        }

    }

}
