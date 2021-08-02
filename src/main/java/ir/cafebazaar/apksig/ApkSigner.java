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

package ir.cafebazaar.apksig;

import static ir.cafebazaar.apksig.apk.ApkUtils.SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME;

import ir.cafebazaar.apksig.apk.ApkFormatException;
import ir.cafebazaar.apksig.apk.ApkSigningBlockNotFoundException;
import ir.cafebazaar.apksig.apk.ApkUtils;
import ir.cafebazaar.apksig.apk.MinSdkVersionException;
import ir.cafebazaar.apksig.internal.apk.v1.DigestAlgorithm;
import ir.cafebazaar.apksig.internal.apk.v1.V1SchemeSigner;
import ir.cafebazaar.apksig.internal.apk.ContentDigestAlgorithm;
import ir.cafebazaar.apksig.internal.util.ByteBufferDataSource;
import ir.cafebazaar.apksig.internal.util.Pair;
import ir.cafebazaar.apksig.internal.zip.CentralDirectoryRecord;
import ir.cafebazaar.apksig.internal.zip.EocdRecord;
import ir.cafebazaar.apksig.internal.zip.LocalFileRecord;
import ir.cafebazaar.apksig.internal.zip.ZipUtils;
import ir.cafebazaar.apksig.util.DataSink;
import ir.cafebazaar.apksig.util.DataSinks;
import ir.cafebazaar.apksig.util.DataSource;
import ir.cafebazaar.apksig.util.DataSources;
import ir.cafebazaar.apksig.util.ReadableDataSink;
import ir.cafebazaar.apksig.zip.ZipFormatException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.lang.ClassNotFoundException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

/**
 * APK signer.
 *
 * <p>The signer preserves as much of the input APK as possible. For example, it preserves the order
 * of APK entries and preserves their contents, including compressed form and alignment of data.
 *
 * <p>Use {@link Builder} to obtain instances of this signer.
 *
 * @see <a href="https://source.android.com/security/apksigning/index.html">Application Signing</a>
 */
public class ApkSigner {

    /**
     * Extensible data block/field header ID used for storing information about alignment of
     * uncompressed entries as well as for aligning the entries's data. See ZIP appnote.txt section
     * 4.5 Extensible data fields.
     */
    private static final short ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID = (short) 0xd935;

    /**
     * Minimum size (in bytes) of the extensible data block/field used for alignment of uncompressed
     * entries.
     */
    private static final short ALIGNMENT_ZIP_EXTRA_DATA_FIELD_MIN_SIZE_BYTES = 6;

    private static final short ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;

    /**
     * Name of the Android manifest ZIP entry in APKs.
     */
    private static final String ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";

    private final List<SignerConfig> mSignerConfigs;
    private final SignerConfig mSourceStampSignerConfig;
    private final SigningCertificateLineage mSourceStampSigningCertificateLineage;
    private final boolean mForceSourceStampOverwrite;
    private final Integer mMinSdkVersion;
    private final boolean mV1SigningEnabled;
    private final boolean mV2SigningEnabled;
    private final boolean mV3SigningEnabled;
    private final boolean mV4SigningEnabled;
    private final boolean mVerityEnabled;
    private final boolean mV4ErrorReportingEnabled;
    private final boolean mDebuggableApkPermitted;
    private final boolean mOtherSignersSignaturesPreserved;
    private final boolean mSignerConfigsDisable;
    private final String mCreatedBy;

    private final ApkSignerEngine mSignerEngine;

    private final File mInputApkFile;
    private final DataSource mInputApkDataSource;

    private final File mOutputApkFile;
    private final DataSink mOutputApkDataSink;
    private final DataSource mOutputApkDataSource;

    private final File mOutputV4File;

    private final File mInputBinFile;
    private final File mOutputBinFile;
    List<BinaryFormat> binaryFormatItems;

    private final SigningCertificateLineage mSigningCertificateLineage;

    private ApkSigner(
            List<SignerConfig> signerConfigs,
            SignerConfig sourceStampSignerConfig,
            SigningCertificateLineage sourceStampSigningCertificateLineage,
            boolean forceSourceStampOverwrite,
            Integer minSdkVersion,
            boolean v1SigningEnabled,
            boolean v2SigningEnabled,
            boolean v3SigningEnabled,
            boolean v4SigningEnabled,
            boolean verityEnabled,
            boolean v4ErrorReportingEnabled,
            boolean debuggableApkPermitted,
            boolean otherSignersSignaturesPreserved,
            boolean signerConfigsDisable,
            String createdBy,
            ApkSignerEngine signerEngine,
            File inputApkFile,
            DataSource inputApkDataSource,
            File outputApkFile,
            DataSink outputApkDataSink,
            DataSource outputApkDataSource,
            File outputV4File,
            File inputBinFile,
            File outputBinFile,
            List<BinaryFormat> binaryFormats,
            SigningCertificateLineage signingCertificateLineage) {

        mSignerConfigs = signerConfigs;
        mSourceStampSignerConfig = sourceStampSignerConfig;
        mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
        mForceSourceStampOverwrite = forceSourceStampOverwrite;
        mMinSdkVersion = minSdkVersion;
        mV1SigningEnabled = v1SigningEnabled;
        mV2SigningEnabled = v2SigningEnabled;
        mV3SigningEnabled = v3SigningEnabled;
        mV4SigningEnabled = v4SigningEnabled;
        mVerityEnabled = verityEnabled;
        mV4ErrorReportingEnabled = v4ErrorReportingEnabled;
        mDebuggableApkPermitted = debuggableApkPermitted;
        mOtherSignersSignaturesPreserved = otherSignersSignaturesPreserved;
        mSignerConfigsDisable = signerConfigsDisable;
        mCreatedBy = createdBy;

        mSignerEngine = signerEngine;

        mInputApkFile = inputApkFile;
        mInputApkDataSource = inputApkDataSource;

        mOutputApkFile = outputApkFile;
        mOutputApkDataSink = outputApkDataSink;
        mOutputApkDataSource = outputApkDataSource;

        mOutputV4File = outputV4File;

        mInputBinFile = inputBinFile;
        mOutputBinFile = outputBinFile;
        binaryFormatItems = binaryFormats;

        mSigningCertificateLineage = signingCertificateLineage;
    }

    public String genV1Bin()
            throws IOException {
        Closeable in = null;
        DataSource inputApk;
        try {
            if (mInputApkFile != null) {
                RandomAccessFile inputFile;
                inputFile = new RandomAccessFile(mInputApkFile, "r");
                in = inputFile;
                inputApk = DataSources.asDataSource(inputFile);
            } else {
                throw new IllegalStateException("Input APK not specified");
            }

            Closeable out = null;
            try {
                try {
                    //  Block of code to try
                    String sign = genV1Bin(inputApk);
                    return sign;
                } catch (Exception e) {
                    //  Block of code to handle errors
                    e.printStackTrace();
                }

            } finally {
                if (out != null) {
                    out.close();
                }
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
        return null;
    }

    private String genV1Bin(DataSource inputApk)
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        DataSink outputApkOut = DataSinks.newInMemoryDataSink();

        List<DigestAlgorithm> v1ContentDigestAlgorithmList = new ArrayList<>();
        v1ContentDigestAlgorithmList.add(DigestAlgorithm.SHA256);
        v1ContentDigestAlgorithmList.add(DigestAlgorithm.SHA1);
        int minSdkVersion = 0;

        ManifestOutputHashMap finalOutput = new ManifestOutputHashMap();

        for (DigestAlgorithm v1ContentDigestAlgorithm : v1ContentDigestAlgorithmList) {
            ManifestOutput manifestOutput = new ManifestOutput();
            // Step 1. Find input APK's main ZIP sections
            ApkUtils.ZipSections inputZipSections;
            try {
                inputZipSections = ApkUtils.findZipSections(inputApk);
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
            }
            long inputApkSigningBlockOffset = -1;
            DataSource inputApkSigningBlock = null;
            try {
                ApkUtils.ApkSigningBlock apkSigningBlockInfo =
                        ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
                inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
                inputApkSigningBlock = apkSigningBlockInfo.getContents();
            } catch (ApkSigningBlockNotFoundException e) {
                // Input APK does not contain an APK Signing Block. That's OK. APKs are not required to
                // contain this block. It's only needed if the APK is signed using APK Signature Scheme
                // v2 and/or v3.
            }
            DataSource inputApkLfhSection =
                    inputApk.slice(
                            0,
                            (inputApkSigningBlockOffset != -1)
                                    ? inputApkSigningBlockOffset
                                    : inputZipSections.getZipCentralDirectoryOffset());

            // Step 2. Parse the input APK's ZIP Central Directory
            ByteBuffer inputCd = getZipCentralDirectory(inputApk, inputZipSections);
            List<CentralDirectoryRecord> inputCdRecords =
                    parseZipCentralDirectory(inputCd, inputZipSections);

            List<Hints.PatternWithRange> pinPatterns =
                    extractPinPatterns(inputCdRecords, inputApkLfhSection);
            List<Hints.ByteRange> pinByteRanges = pinPatterns == null ? null : new ArrayList<>();

            // Step 3. Obtain a signer engine instance
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, inputApkLfhSection);
            }

            ApkSignerEngine signerEngine = obtainSignerEngine
                    (
                            minSdkVersion,
                            mSignerConfigsDisable,
                            v1ContentDigestAlgorithm,
                            mV2SigningEnabled,
                            mV3SigningEnabled
                    );

            // Step 4. Provide the signer engine with the input APK's APK Signing Block (if any)
            if (inputApkSigningBlock != null) {
                signerEngine.inputApkSigningBlock(inputApkSigningBlock);
            }

            // Step 5. Iterate over input APK's entries and output the Local File Header + data of those
            // entries which need to be output. Entries are iterated in the order in which their Local
            // File Header records are stored in the file. This is to achieve better data locality in
            // case Central Directory entries are in the wrong order.
            List<CentralDirectoryRecord> inputCdRecordsSortedByLfhOffset =
                    new ArrayList<>(inputCdRecords);
            Collections.sort(
                    inputCdRecordsSortedByLfhOffset,
                    CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
            int lastModifiedDateForNewEntries = -1;
            int lastModifiedTimeForNewEntries = -1;
            long inputOffset = 0;
            long outputOffset = 0;
            byte[] sourceStampCertificateDigest = null;
            Map<String, CentralDirectoryRecord> outputCdRecordsByName =
                    new HashMap<>(inputCdRecords.size());
            for (final CentralDirectoryRecord inputCdRecord : inputCdRecordsSortedByLfhOffset) {
                String entryName = inputCdRecord.getName();
                if (Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME.equals(entryName)) {
                    continue; // We'll re-add below if needed.
                }
                if (SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.equals(entryName)) {
                    try {
                        sourceStampCertificateDigest =
                                LocalFileRecord.getUncompressedData(
                                        inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                    } catch (ZipFormatException ex) {
                        throw new ApkFormatException("Bad source stamp entry");
                    }
                    continue; // Existing source stamp is handled below as needed.
                }
                ApkSignerEngine.InputJarEntryInstructions entryInstructions =
                        signerEngine.inputJarEntry(entryName);
                boolean shouldOutput;
                switch (entryInstructions.getOutputPolicy()) {
                    case OUTPUT:
                        shouldOutput = true;
                        break;
                    case OUTPUT_BY_ENGINE:
                    case SKIP:
                        shouldOutput = false;
                        break;
                    default:
                        throw new RuntimeException(
                                "Unknown output policy: " + entryInstructions.getOutputPolicy());
                }

                long inputLocalFileHeaderStartOffset = inputCdRecord.getLocalFileHeaderOffset();
                if (inputLocalFileHeaderStartOffset > inputOffset) {
                    // Unprocessed data in input starting at inputOffset and ending and the start of
                    // this record's LFH. We output this data verbatim because this signer is supposed
                    // to preserve as much of input as possible.
                    long chunkSize = inputLocalFileHeaderStartOffset - inputOffset;
                    inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
                    outputOffset += chunkSize;
                    inputOffset = inputLocalFileHeaderStartOffset;
                }
                LocalFileRecord inputLocalFileRecord;
                try {
                    inputLocalFileRecord =
                            LocalFileRecord.getRecord(
                                    inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                } catch (ZipFormatException e) {
                    throw new ApkFormatException("Malformed ZIP entry: " + inputCdRecord.getName(), e);
                }
                inputOffset += inputLocalFileRecord.getSize();

                ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest =
                        entryInstructions.getInspectJarEntryRequest();
                if (inspectEntryRequest != null) {
                    fulfillInspectInputJarEntryRequest(
                            inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                }

                if (shouldOutput) {
                    // Find the max value of last modified, to be used for new entries added by the
                    // signer.
                    int lastModifiedDate = inputCdRecord.getLastModificationDate();
                    int lastModifiedTime = inputCdRecord.getLastModificationTime();
                    if ((lastModifiedDateForNewEntries == -1)
                            || (lastModifiedDate > lastModifiedDateForNewEntries)
                            || ((lastModifiedDate == lastModifiedDateForNewEntries)
                            && (lastModifiedTime > lastModifiedTimeForNewEntries))) {
                        lastModifiedDateForNewEntries = lastModifiedDate;
                        lastModifiedTimeForNewEntries = lastModifiedTime;
                    }

                    inspectEntryRequest = signerEngine.outputJarEntry(entryName);
                    if (inspectEntryRequest != null) {
                        fulfillInspectInputJarEntryRequest(
                                inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                    }

                    // Output entry's Local File Header + data
                    long outputLocalFileHeaderOffset = outputOffset;
                    OutputSizeAndDataOffset outputLfrResult =
                            outputInputJarEntryLfhRecordPreservingDataAlignment(
                                    inputApkLfhSection,
                                    inputLocalFileRecord,
                                    outputApkOut,
                                    outputLocalFileHeaderOffset);
                    outputOffset += outputLfrResult.outputBytes;
                    long outputDataOffset =
                            outputLocalFileHeaderOffset + outputLfrResult.dataOffsetBytes;

                    if (pinPatterns != null) {
                        boolean pinFileHeader = false;
                        for (Hints.PatternWithRange pinPattern : pinPatterns) {
                            if (pinPattern.matcher(inputCdRecord.getName()).matches()) {
                                Hints.ByteRange dataRange =
                                        new Hints.ByteRange(outputDataOffset, outputOffset);
                                Hints.ByteRange pinRange =
                                        pinPattern.ClampToAbsoluteByteRange(dataRange);
                                if (pinRange != null) {
                                    pinFileHeader = true;
                                    pinByteRanges.add(pinRange);
                                }
                            }
                        }
                        if (pinFileHeader) {
                            pinByteRanges.add(
                                    new Hints.ByteRange(outputLocalFileHeaderOffset, outputDataOffset));
                        }
                    }

                    // Enqueue entry's Central Directory record for output
                    CentralDirectoryRecord outputCdRecord;
                    if (outputLocalFileHeaderOffset == inputLocalFileRecord.getStartOffsetInArchive()) {
                        outputCdRecord = inputCdRecord;
                    } else {
                        outputCdRecord =
                                inputCdRecord.createWithModifiedLocalFileHeaderOffset(
                                        outputLocalFileHeaderOffset);
                    }
                    outputCdRecordsByName.put(entryName, outputCdRecord);
                }
            }
            long inputLfhSectionSize = inputApkLfhSection.size();
            if (inputOffset < inputLfhSectionSize) {
                // Unprocessed data in input starting at inputOffset and ending and the end of the input
                // APK's LFH section. We output this data verbatim because this signer is supposed
                // to preserve as much of input as possible.
                long chunkSize = inputLfhSectionSize - inputOffset;
                inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
                outputOffset += chunkSize;
                inputOffset = inputLfhSectionSize;
            }

            // Step 6. Sort output APK's Central Directory records in the order in which they should
            // appear in the output
            List<CentralDirectoryRecord> outputCdRecords = new ArrayList<>(inputCdRecords.size() + 10);
            for (CentralDirectoryRecord inputCdRecord : inputCdRecords) {
                String entryName = inputCdRecord.getName();
                CentralDirectoryRecord outputCdRecord = outputCdRecordsByName.get(entryName);
                if (outputCdRecord != null) {
                    outputCdRecords.add(outputCdRecord);
                }
            }

            if (lastModifiedDateForNewEntries == -1) {
                lastModifiedDateForNewEntries = 0x3a21; // Jan 1 2009 (DOS)
                lastModifiedTimeForNewEntries = 0;
            }

            // Step 7. Generate and output SourceStamp certificate hash, if necessary. This may output
            // more Local File Header + data entries and add to the list of output Central Directory
            // records.
            if (signerEngine.isEligibleForSourceStamp()) {
                byte[] uncompressedData = signerEngine.generateSourceStampCertificateDigest();
                if (mForceSourceStampOverwrite
                        || sourceStampCertificateDigest == null
                        || Arrays.equals(uncompressedData, sourceStampCertificateDigest)) {
                    outputOffset +=
                            outputDataToOutputApk(
                                    SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME,
                                    uncompressedData,
                                    outputOffset,
                                    outputCdRecords,
                                    lastModifiedTimeForNewEntries,
                                    lastModifiedDateForNewEntries,
                                    outputApkOut);
                } else {
                    throw new ApkFormatException(
                            String.format(
                                    "Cannot generate SourceStamp. APK contains an existing entry with"
                                            + " the name: %s, and it is different than the provided source"
                                            + " stamp certificate",
                                    SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME));
                }
            }

            V1SchemeSigner.OutputManifestFile manifestFile =
                    signerEngine.outputManifestFile();
            V1SchemeSigner.OutputManifestFileSerilizable manifestFileSerilizable = new V1SchemeSigner.OutputManifestFileSerilizable(manifestFile);
            manifestOutput.manifestFile = manifestFileSerilizable;

            finalOutput.manifestOutputHashMap.put(v1ContentDigestAlgorithm, manifestOutput);
        }
        finalOutput.minSdkVersion = minSdkVersion;
        finalOutput.v2SigningEnabled = mV2SigningEnabled;
        finalOutput.v3SigningEnabled = mV3SigningEnabled;
        String finalOutputBase64 = BinaryFormat.toBase64String(finalOutput);
        BinaryFormat signV1Output = new BinaryFormat();
        signV1Output.identifier = mInputApkFile.getAbsolutePath();
        signV1Output.content = finalOutputBase64;

        List<BinaryFormat> binaryFormatOutputGroup = new ArrayList<>();
        binaryFormatOutputGroup.add(signV1Output);
        return binaryFormatOutputGroup.get(0).content;
    }

    public String signV1() {

        try {
            String sign = doSignV1();
            return sign;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private String doSignV1()
            throws IOException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, ClassNotFoundException {


        List<BinaryFormat> inputBinaryList;
        if(binaryFormatItems != null)
            inputBinaryList = binaryFormatItems;
        else
            inputBinaryList = loadInputBinFile();

        List<BinaryFormat> outputBinaryList = new ArrayList<>();

        for (BinaryFormat binaryFormat : inputBinaryList) {
            BinaryFormat outputBinaryItem = new BinaryFormat();
            outputBinaryItem.identifier = binaryFormat.identifier;

            ManifestOutputHashMap content = (ManifestOutputHashMap) BinaryFormat.fromBase64String(binaryFormat.content);
            DigestAlgorithm v1ContentDigestAlgorithm;
            ApkSignerEngine signerEngine = obtainSignerEngine
                    (
                            content.minSdkVersion,
                            mSignerConfigsDisable,
                            null,
                            content.v2SigningEnabled,
                            content.v3SigningEnabled
                    );
            v1ContentDigestAlgorithm = signerEngine.getV1ContentDigestAlgorithm();

            V1SchemeSigner.OutputManifestFileSerilizable manifestFileSerilizable = content.manifestOutputHashMap.get(v1ContentDigestAlgorithm).manifestFile;
            V1SchemeSigner.OutputManifestFile manifestFile = new V1SchemeSigner.OutputManifestFile(manifestFileSerilizable);
            ApkSignerEngine.OutputJarSignatureRequest outputJarSignatureRequest =
                    signerEngine.outputSignatureV1(manifestFile);

            outputBinaryItem.content = BinaryFormat.toBase64String(outputJarSignatureRequest);
            outputBinaryList.add(outputBinaryItem);
        }
        return outputBinaryList.get(0).content;
    }

    public void addSignV1ToApk() {
        try {
            addSignV1ToApk(mOutputApkFile);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void addSignV1ToApk(File mOutputApkFile) throws IOException, ApkFormatException, InvalidKeyException,
            SignatureException, ClassNotFoundException {

        List<BinaryFormat> inputBinaryList;
        if(binaryFormatItems != null)
            inputBinaryList = binaryFormatItems;
        else
            inputBinaryList = loadInputBinFile();

        BinaryFormat inputBinary = inputBinaryList.get(0);
        Closeable in = null;
        Closeable out = null;
        try {
            String inputApkName = inputBinary.identifier;

            File inputApkFile = new File(inputApkName);
            File outputApkFile = mOutputApkFile;

            DataSource inputApk;
            DataSink outputApkOut;


            RandomAccessFile inputFile = new RandomAccessFile(inputApkFile, "r");
            in = inputFile;
            inputApk = DataSources.asDataSource(inputFile);

            RandomAccessFile outputFile = new RandomAccessFile(outputApkFile, "rw");
            out = outputFile;
            outputFile.setLength(0);
            outputApkOut = DataSinks.asDataSink(outputFile);

            ApkSignerEngine.OutputJarSignatureRequest outputJarSignatureRequest =
                    (ApkSignerEngine.OutputJarSignatureRequest) BinaryFormat.fromBase64String(inputBinary.content);

            // Step 1. Find input APK's main ZIP sections
            ApkUtils.ZipSections inputZipSections;
            try {
                inputZipSections = ApkUtils.findZipSections(inputApk);
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
            }
            long inputApkSigningBlockOffset = -1;
            DataSource inputApkSigningBlock = null;
            try {
                ApkUtils.ApkSigningBlock apkSigningBlockInfo =
                        ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
                inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
                inputApkSigningBlock = apkSigningBlockInfo.getContents();
            } catch (ApkSigningBlockNotFoundException e) {
                // Input APK does not contain an APK Signing Block. That's OK. APKs are not required to
                // contain this block. It's only needed if the APK is signed using APK Signature Scheme
                // v2 and/or v3.
            }
            DataSource inputApkLfhSection =
                    inputApk.slice(
                            0,
                            (inputApkSigningBlockOffset != -1)
                                    ? inputApkSigningBlockOffset
                                    : inputZipSections.getZipCentralDirectoryOffset());

            // Step 2. Parse the input APK's ZIP Central Directory
            ByteBuffer inputCd = getZipCentralDirectory(inputApk, inputZipSections);
            List<CentralDirectoryRecord> inputCdRecords =
                    parseZipCentralDirectory(inputCd, inputZipSections);

            List<Hints.PatternWithRange> pinPatterns =
                    extractPinPatterns(inputCdRecords, inputApkLfhSection);
            List<Hints.ByteRange> pinByteRanges = pinPatterns == null ? null : new ArrayList<>();

            // Step 3. Obtain a signer engine instance
            int minSdkVersion;
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, inputApkLfhSection);
            }
            DigestAlgorithm v1ContentDigestAlgorithm = DigestAlgorithm.SHA1;
            ApkSignerEngine signerEngine = obtainSignerEngine
                    (
                            minSdkVersion,
                            mSignerConfigsDisable,
                            v1ContentDigestAlgorithm,
                            mV2SigningEnabled,
                            mV3SigningEnabled
                    );


            // Step 4. Provide the signer engine with the input APK's APK Signing Block (if any)
            if (inputApkSigningBlock != null) {
                signerEngine.inputApkSigningBlock(inputApkSigningBlock);
            }

            // Step 5. Iterate over input APK's entries and output the Local File Header + data of those
            // entries which need to be output. Entries are iterated in the order in which their Local
            // File Header records are stored in the file. This is to achieve better data locality in
            // case Central Directory entries are in the wrong order.
            List<CentralDirectoryRecord> inputCdRecordsSortedByLfhOffset =
                    new ArrayList<>(inputCdRecords);
            Collections.sort(
                    inputCdRecordsSortedByLfhOffset,
                    CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
            int lastModifiedDateForNewEntries = -1;
            int lastModifiedTimeForNewEntries = -1;
            long inputOffset = 0;
            long outputOffset = 0;
            byte[] sourceStampCertificateDigest = null;
            Map<String, CentralDirectoryRecord> outputCdRecordsByName =
                    new HashMap<>(inputCdRecords.size());
            for (final CentralDirectoryRecord inputCdRecord : inputCdRecordsSortedByLfhOffset) {
                String entryName = inputCdRecord.getName();
                if (Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME.equals(entryName)) {
                    continue; // We'll re-add below if needed.
                }
                if (SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.equals(entryName)) {
                    try {
                        sourceStampCertificateDigest =
                                LocalFileRecord.getUncompressedData(
                                        inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                    } catch (ZipFormatException ex) {
                        throw new ApkFormatException("Bad source stamp entry");
                    }
                    continue; // Existing source stamp is handled below as needed.
                }
                ApkSignerEngine.InputJarEntryInstructions entryInstructions =
                        signerEngine.inputJarEntry(entryName);
                boolean shouldOutput;
                switch (entryInstructions.getOutputPolicy()) {
                    case OUTPUT:
                        shouldOutput = true;
                        break;
                    case OUTPUT_BY_ENGINE:
                    case SKIP:
                        shouldOutput = false;
                        break;
                    default:
                        throw new RuntimeException(
                                "Unknown output policy: " + entryInstructions.getOutputPolicy());
                }

                long inputLocalFileHeaderStartOffset = inputCdRecord.getLocalFileHeaderOffset();
                if (inputLocalFileHeaderStartOffset > inputOffset) {
                    // Unprocessed data in input starting at inputOffset and ending and the start of
                    // this record's LFH. We output this data verbatim because this signer is supposed
                    // to preserve as much of input as possible.
                    long chunkSize = inputLocalFileHeaderStartOffset - inputOffset;
                    inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
                    outputOffset += chunkSize;
                    inputOffset = inputLocalFileHeaderStartOffset;
                }
                LocalFileRecord inputLocalFileRecord;
                try {
                    inputLocalFileRecord =
                            LocalFileRecord.getRecord(
                                    inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                } catch (ZipFormatException e) {
                    throw new ApkFormatException("Malformed ZIP entry: " + inputCdRecord.getName(), e);
                }
                inputOffset += inputLocalFileRecord.getSize();

                ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest =
                        entryInstructions.getInspectJarEntryRequest();
                if (inspectEntryRequest != null) {
                    fulfillInspectInputJarEntryRequest(
                            inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                }

                if (shouldOutput) {
                    // Find the max value of last modified, to be used for new entries added by the
                    // signer.
                    int lastModifiedDate = inputCdRecord.getLastModificationDate();
                    int lastModifiedTime = inputCdRecord.getLastModificationTime();
                    if ((lastModifiedDateForNewEntries == -1)
                            || (lastModifiedDate > lastModifiedDateForNewEntries)
                            || ((lastModifiedDate == lastModifiedDateForNewEntries)
                            && (lastModifiedTime > lastModifiedTimeForNewEntries))) {
                        lastModifiedDateForNewEntries = lastModifiedDate;
                        lastModifiedTimeForNewEntries = lastModifiedTime;
                    }

                    inspectEntryRequest = signerEngine.outputJarEntry(entryName);
                    if (inspectEntryRequest != null) {
                        fulfillInspectInputJarEntryRequest(
                                inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                    }

                    // Output entry's Local File Header + data
                    long outputLocalFileHeaderOffset = outputOffset;
                    OutputSizeAndDataOffset outputLfrResult =
                            outputInputJarEntryLfhRecordPreservingDataAlignment(
                                    inputApkLfhSection,
                                    inputLocalFileRecord,
                                    outputApkOut,
                                    outputLocalFileHeaderOffset);
                    outputOffset += outputLfrResult.outputBytes;
                    long outputDataOffset =
                            outputLocalFileHeaderOffset + outputLfrResult.dataOffsetBytes;

                    if (pinPatterns != null) {
                        boolean pinFileHeader = false;
                        for (Hints.PatternWithRange pinPattern : pinPatterns) {
                            if (pinPattern.matcher(inputCdRecord.getName()).matches()) {
                                Hints.ByteRange dataRange =
                                        new Hints.ByteRange(outputDataOffset, outputOffset);
                                Hints.ByteRange pinRange =
                                        pinPattern.ClampToAbsoluteByteRange(dataRange);
                                if (pinRange != null) {
                                    pinFileHeader = true;
                                    pinByteRanges.add(pinRange);
                                }
                            }
                        }
                        if (pinFileHeader) {
                            pinByteRanges.add(
                                    new Hints.ByteRange(outputLocalFileHeaderOffset, outputDataOffset));
                        }
                    }

                    // Enqueue entry's Central Directory record for output
                    CentralDirectoryRecord outputCdRecord;
                    if (outputLocalFileHeaderOffset == inputLocalFileRecord.getStartOffsetInArchive()) {
                        outputCdRecord = inputCdRecord;
                    } else {
                        outputCdRecord =
                                inputCdRecord.createWithModifiedLocalFileHeaderOffset(
                                        outputLocalFileHeaderOffset);
                    }
                    outputCdRecordsByName.put(entryName, outputCdRecord);
                }
            }
            long inputLfhSectionSize = inputApkLfhSection.size();
            if (inputOffset < inputLfhSectionSize) {
                // Unprocessed data in input starting at inputOffset and ending and the end of the input
                // APK's LFH section. We output this data verbatim because this signer is supposed
                // to preserve as much of input as possible.
                long chunkSize = inputLfhSectionSize - inputOffset;
                inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
                outputOffset += chunkSize;
                inputOffset = inputLfhSectionSize;
            }

            // Step 6. Sort output APK's Central Directory records in the order in which they should
            // appear in the output
            List<CentralDirectoryRecord> outputCdRecords = new ArrayList<>(inputCdRecords.size() + 10);
            for (CentralDirectoryRecord inputCdRecord : inputCdRecords) {
                String entryName = inputCdRecord.getName();
                CentralDirectoryRecord outputCdRecord = outputCdRecordsByName.get(entryName);
                if (outputCdRecord != null) {
                    outputCdRecords.add(outputCdRecord);
                }
            }

            if (lastModifiedDateForNewEntries == -1) {
                lastModifiedDateForNewEntries = 0x3a21; // Jan 1 2009 (DOS)
                lastModifiedTimeForNewEntries = 0;
            }

            // Step 7. Generate and output SourceStamp certificate hash, if necessary. This may output
            // more Local File Header + data entries and add to the list of output Central Directory
            // records.
            if (signerEngine.isEligibleForSourceStamp()) {
                byte[] uncompressedData = signerEngine.generateSourceStampCertificateDigest();
                if (mForceSourceStampOverwrite
                        || sourceStampCertificateDigest == null
                        || Arrays.equals(uncompressedData, sourceStampCertificateDigest)) {
                    outputOffset +=
                            outputDataToOutputApk(
                                    SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME,
                                    uncompressedData,
                                    outputOffset,
                                    outputCdRecords,
                                    lastModifiedTimeForNewEntries,
                                    lastModifiedDateForNewEntries,
                                    outputApkOut);
                } else {
                    throw new ApkFormatException(
                            String.format(
                                    "Cannot generate SourceStamp. APK contains an existing entry with"
                                            + " the name: %s, and it is different than the provided source"
                                            + " stamp certificate",
                                    SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME));
                }
            }

            // Step 8. Generate and output JAR signatures, if necessary. This may output more Local File
            // Header + data entries and add to the list of output Central Directory records.
            signerEngine.setAddV1SignatureRequest(outputJarSignatureRequest);
            if (outputJarSignatureRequest != null) {
                for (ApkSignerEngine.OutputJarSignatureRequest.JarEntry entry :
                        outputJarSignatureRequest.getAdditionalJarEntries()) {
                    String entryName = entry.getName();
                    byte[] uncompressedData = entry.getData();

                    ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest =
                            signerEngine.outputJarEntry(entryName);
                    if (inspectEntryRequest != null) {
                        inspectEntryRequest
                                .getDataSink()
                                .consume(uncompressedData, 0, uncompressedData.length);
                        inspectEntryRequest.done();
                    }

                    outputOffset +=
                            outputDataToOutputApk(
                                    entryName,
                                    uncompressedData,
                                    outputOffset,
                                    outputCdRecords,
                                    lastModifiedTimeForNewEntries,
                                    lastModifiedDateForNewEntries,
                                    outputApkOut);
                }
                outputJarSignatureRequest.done();
            }

            if (pinByteRanges != null) {
                pinByteRanges.add(new Hints.ByteRange(outputOffset, Long.MAX_VALUE)); // central dir
                String entryName = Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME;
                byte[] uncompressedData = Hints.encodeByteRangeList(pinByteRanges);
                outputOffset +=
                        outputDataToOutputApk(
                                entryName,
                                uncompressedData,
                                outputOffset,
                                outputCdRecords,
                                lastModifiedTimeForNewEntries,
                                lastModifiedDateForNewEntries,
                                outputApkOut);
            }

            // Step 9. Construct output ZIP Central Directory in an in-memory buffer
            long outputCentralDirSizeBytes = 0;
            for (CentralDirectoryRecord record : outputCdRecords) {
                outputCentralDirSizeBytes += record.getSize();
            }
            if (outputCentralDirSizeBytes > Integer.MAX_VALUE) {
                throw new IOException(
                        "Output ZIP Central Directory too large: "
                                + outputCentralDirSizeBytes
                                + " bytes");
            }
            ByteBuffer outputCentralDir = ByteBuffer.allocate((int) outputCentralDirSizeBytes);
            for (CentralDirectoryRecord record : outputCdRecords) {
                record.copyTo(outputCentralDir);
            }
            outputCentralDir.flip();
            DataSource outputCentralDirDataSource = new ByteBufferDataSource(outputCentralDir);
            long outputCentralDirStartOffset = outputOffset;
            int outputCentralDirRecordCount = outputCdRecords.size();

            // Step 10. Construct output ZIP End of Central Directory record in an in-memory buffer
            ByteBuffer outputEocd =
                    EocdRecord.createWithModifiedCentralDirectoryInfo(
                            inputZipSections.getZipEndOfCentralDirectory(),
                            outputCentralDirRecordCount,
                            outputCentralDirDataSource.size(),
                            outputCentralDirStartOffset);

            // Step 12. Output ZIP Central Directory and ZIP End of Central Directory
            outputCentralDirDataSource.feed(0, outputCentralDirDataSource.size(), outputApkOut);
            outputApkOut.consume(outputEocd);

            byte[] apkSigingBlock = new byte[1];
            int paddingBefore = 0;

            signerEngine.setAddSigningBlockRequest(apkSigingBlock, paddingBefore);
            signerEngine.outputDone();

        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }
    }

    public String getContentDigestsV2V3Cafebazaar()
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IllegalStateException {
        Closeable in = null;
        DataSource inputApk;
        try {
            if (mInputApkDataSource != null) {
                inputApk = mInputApkDataSource;
            } else if (mInputApkFile != null) {
                RandomAccessFile inputFile = new RandomAccessFile(mInputApkFile, "r");
                in = inputFile;
                inputApk = DataSources.asDataSource(inputFile);
            } else {
                throw new IllegalStateException("Input APK not specified");
            }
            Pair<Map<ContentDigestAlgorithm, byte[]>, Integer> contentDigestsAndMinSdkVersion =
                    getContentDigestsV2V3Cafebazaar(inputApk);
            SerializableContentDigestsAndMinSdkVersion serializableContentDigestsAndMinSdkVersion =
                    new SerializableContentDigestsAndMinSdkVersion(contentDigestsAndMinSdkVersion);
            BinaryFormat binaryFormatOutputItem =
                    new BinaryFormat(mInputApkFile.getAbsolutePath(), serializableContentDigestsAndMinSdkVersion);

            return binaryFormatOutputItem.content;
        } finally {
            if (in != null) {
                in.close();
            }
        }

    }

    private Pair<Map<ContentDigestAlgorithm, byte[]>, Integer> getContentDigestsV2V3Cafebazaar(
            DataSource inputApk)
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        // Step 1. Find input APK's main ZIP sections
        ApkUtils.ZipSections inputZipSections;
        try {
            inputZipSections = ApkUtils.findZipSections(inputApk);
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
        }
        long inputApkSigningBlockOffset = -1;
        DataSource inputApkSigningBlock = null;
        try {
            ApkUtils.ApkSigningBlock apkSigningBlockInfo =
                    ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
            inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
            inputApkSigningBlock = apkSigningBlockInfo.getContents();
        } catch (ApkSigningBlockNotFoundException e) {
            // Input APK does not contain an APK Signing Block. That's OK. APKs are not required to
            // contain this block. It's only needed if the APK is signed using APK Signature Scheme
            // v2 and/or v3.
        }
        DataSource zipEntries =
                inputApk.slice(
                        0,
                        (inputApkSigningBlockOffset != -1)
                                ? inputApkSigningBlockOffset
                                : inputZipSections.getZipCentralDirectoryOffset());
        DataSource zipCentralDirectory = new ByteBufferDataSource(getZipCentralDirectory(inputApk, inputZipSections));
        DataSource zipEocd = new ByteBufferDataSource(inputZipSections.getZipEndOfCentralDirectory());

        // Step 2. Parse the input APK's ZIP Central Directory
        ByteBuffer inputCd = getZipCentralDirectory(inputApk, inputZipSections);
        List<CentralDirectoryRecord> inputCdRecords =
                parseZipCentralDirectory(inputCd, inputZipSections);

        // Step 3. Obtain a signer engine instance
        int _minSdkVersion = 1;
        ApkSignerEngine signerEngine;
        if (mSignerEngine != null) {
            // Use the provided signer engine
            signerEngine = mSignerEngine;
        } else {
            // Construct a signer engine from the provided parameters
            int minSdkVersion;
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, zipEntries);
            }
            _minSdkVersion = minSdkVersion;
            List<DefaultApkSignerEngine.SignerConfig> engineSignerConfigs =
                    new ArrayList<>(mSignerConfigs.size());
            for (SignerConfig signerConfig : mSignerConfigs) {
                engineSignerConfigs.add(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                signerConfig.getName(),
                                signerConfig.getPrivateKey(),
                                signerConfig.getCertificates())
                                .build());
            }
            DefaultApkSignerEngine.Builder signerEngineBuilder =
                    new DefaultApkSignerEngine.Builder(engineSignerConfigs, minSdkVersion, mSignerConfigsDisable)
                            .setV1SigningEnabled(mV1SigningEnabled)
                            .setV2SigningEnabled(mV2SigningEnabled)
                            .setV3SigningEnabled(mV3SigningEnabled)
                            .setVerityEnabled(mVerityEnabled)
                            .setDebuggableApkPermitted(mDebuggableApkPermitted)
                            .setOtherSignersSignaturesPreserved(mOtherSignersSignaturesPreserved)
                            .setSigningCertificateLineage(mSigningCertificateLineage);
            if (mCreatedBy != null) {
                signerEngineBuilder.setCreatedBy(mCreatedBy);
            }
            if (mSourceStampSignerConfig != null) {
                signerEngineBuilder.setStampSignerConfig(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                mSourceStampSignerConfig.getName(),
                                mSourceStampSignerConfig.getPrivateKey(),
                                mSourceStampSignerConfig.getCertificates())
                                .build());
            }
            if (mSourceStampSigningCertificateLineage != null) {
                signerEngineBuilder.setSourceStampSigningCertificateLineage(
                        mSourceStampSigningCertificateLineage);
            }
            signerEngine = signerEngineBuilder.build();
        }

        // Step 4. Provide the signer engine with the input APK's APK Signing Block (if any)
        if (inputApkSigningBlock != null) {
            signerEngine.inputApkSigningBlock(inputApkSigningBlock);
        }

        // Step 11. Generate and output APK Signature Scheme v2 and/or v3 signatures and/or
        // SourceStamp signatures, if necessary.
        // This may insert an APK Signing Block just before the output's ZIP Central Directory
        Map<ContentDigestAlgorithm, byte[]> contentDigests =
                signerEngine.getContentDigestsV2V3Cafebazaar(
                        zipEntries,
                        zipCentralDirectory,
                        zipEocd);

        return Pair.of(contentDigests, _minSdkVersion);
    }

    public String signContentDigestsV2V3Cafebazaar()
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IllegalStateException, ClassNotFoundException {

        List<BinaryFormat> binaryFormatInputGroup;
        if(binaryFormatItems != null)
            binaryFormatInputGroup = binaryFormatItems;
        else
            binaryFormatInputGroup = loadInputBinFile();

        List<BinaryFormat> binaryFormatOutputGroup = new ArrayList<>();
        for (BinaryFormat binaryFormatInputItem : binaryFormatInputGroup) {
            SerializableContentDigestsAndMinSdkVersion serializableContentDigestsAndMinSdkVersion =
                    (SerializableContentDigestsAndMinSdkVersion) BinaryFormat.fromBase64String(binaryFormatInputItem.content);
            Pair<Map<ContentDigestAlgorithm, byte[]>, Integer> contentDigestsAndMinSdkVersion =
                    serializableContentDigestsAndMinSdkVersion.toContentDigestsAndMinSdkVersion();
            byte[] apkSigningBlock = signContentDigestsV2V3Cafebazaar(contentDigestsAndMinSdkVersion);
            SerializableApkSigningBlock serializableApkSigningBlock = new SerializableApkSigningBlock(apkSigningBlock);
            String identifier = binaryFormatInputItem.identifier;
            BinaryFormat binaryFormatOutputItem = new BinaryFormat(identifier, serializableApkSigningBlock);
            binaryFormatOutputGroup.add(binaryFormatOutputItem);
        }
        return binaryFormatOutputGroup.get(0).content;
    }

    private byte[] signContentDigestsV2V3Cafebazaar(
            Pair<Map<ContentDigestAlgorithm, byte[]>, Integer> contentDigestsAndMinSdkVersion)
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Map<ContentDigestAlgorithm, byte[]> contentDigests = contentDigestsAndMinSdkVersion.getFirst();
        int _minSdkVersion = contentDigestsAndMinSdkVersion.getSecond();

        // Step 3. Obtain a signer engine instance
        ApkSignerEngine signerEngine;
        if (mSignerEngine != null) {
            // Use the provided signer engine
            signerEngine = mSignerEngine;
        } else {
            // Construct a signer engine from the provided parameters
            int minSdkVersion;
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = _minSdkVersion;
            }
            List<DefaultApkSignerEngine.SignerConfig> engineSignerConfigs =
                    new ArrayList<>(mSignerConfigs.size());
            for (SignerConfig signerConfig : mSignerConfigs) {
                engineSignerConfigs.add(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                signerConfig.getName(),
                                signerConfig.getPrivateKey(),
                                signerConfig.getCertificates())
                                .build());
            }
            DefaultApkSignerEngine.Builder signerEngineBuilder =
                    new DefaultApkSignerEngine.Builder(engineSignerConfigs, minSdkVersion, mSignerConfigsDisable)
                            .setV1SigningEnabled(mV1SigningEnabled)
                            .setV2SigningEnabled(mV2SigningEnabled)
                            .setV3SigningEnabled(mV3SigningEnabled)
                            .setVerityEnabled(mVerityEnabled)
                            .setDebuggableApkPermitted(mDebuggableApkPermitted)
                            .setOtherSignersSignaturesPreserved(mOtherSignersSignaturesPreserved)
                            .setSigningCertificateLineage(mSigningCertificateLineage);
            if (mCreatedBy != null) {
                signerEngineBuilder.setCreatedBy(mCreatedBy);
            }
            if (mSourceStampSignerConfig != null) {
                signerEngineBuilder.setStampSignerConfig(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                mSourceStampSignerConfig.getName(),
                                mSourceStampSignerConfig.getPrivateKey(),
                                mSourceStampSignerConfig.getCertificates())
                                .build());
            }
            if (mSourceStampSigningCertificateLineage != null) {
                signerEngineBuilder.setSourceStampSigningCertificateLineage(
                        mSourceStampSigningCertificateLineage);
            }
            signerEngine = signerEngineBuilder.build();
        }

        // Step 11. Generate and output APK Signature Scheme v2 and/or v3 signatures and/or
        // SourceStamp signatures, if necessary.
        // This may insert an APK Signing Block just before the output's ZIP Central Directory
        byte[] apkSigningBlock = signerEngine.signContentDigestsV2V3Cafebazaar(contentDigests);

        return apkSigningBlock;
    }

    public void addSignedContentDigestsV2V3Cafebazaar()
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IllegalStateException, ClassNotFoundException {
        Closeable in = null;
        DataSource inputApk;
        try {
            if (mInputApkDataSource != null) {
                inputApk = mInputApkDataSource;
            } else if (mInputApkFile != null) {
                RandomAccessFile inputFile = new RandomAccessFile(mInputApkFile, "r");
                in = inputFile;
                inputApk = DataSources.asDataSource(inputFile);
            } else {
                throw new IllegalStateException("Input APK not specified");
            }

            Closeable out = null;
            try {
                DataSink outputApkOut;
                if (mOutputApkDataSink != null) {
                    outputApkOut = mOutputApkDataSink;
                } else if (mOutputApkFile != null) {
                    RandomAccessFile outputFile = new RandomAccessFile(mOutputApkFile, "rw");
                    out = outputFile;
                    outputFile.setLength(0);
                    outputApkOut = DataSinks.asDataSink(outputFile);
                } else {
                    throw new IllegalStateException("Output APK not specified");
                }

                List<BinaryFormat> binaryFormatInputGroup;
                if(binaryFormatItems != null)
                    binaryFormatInputGroup = binaryFormatItems;
                else
                    binaryFormatInputGroup = loadInputBinFile();

                BinaryFormat binaryFormatInputItem = binaryFormatInputGroup.get(0);
                SerializableApkSigningBlock serializableApkSigningBlock =
                        (SerializableApkSigningBlock) BinaryFormat.fromBase64String(binaryFormatInputItem.content);
                byte[] apkSigningBlock = serializableApkSigningBlock.toApkSigningBlock();
                addSignedContentDigestsV2V3Cafebazaar(inputApk, outputApkOut, apkSigningBlock);
            } finally {
                if (out != null) {
                    out.close();
                }
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private void addSignedContentDigestsV2V3Cafebazaar(
            DataSource inputApk, DataSink outputApkOut, byte[] apkSigningBlock)
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        // Step 1. Find input APK's main ZIP sections
        ApkUtils.ZipSections inputZipSections;
        try {
            inputZipSections = ApkUtils.findZipSections(inputApk);
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
        }
        long inputApkSigningBlockOffset = -1;
        DataSource inputApkSigningBlock = null;
        try {
            ApkUtils.ApkSigningBlock apkSigningBlockInfo =
                    ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
            inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
            inputApkSigningBlock = apkSigningBlockInfo.getContents();
        } catch (ApkSigningBlockNotFoundException e) {
            // Input APK does not contain an APK Signing Block. That's OK. APKs are not required to
            // contain this block. It's only needed if the APK is signed using APK Signature Scheme
            // v2 and/or v3.
        }
        DataSource zipEntries =
                inputApk.slice(
                        0,
                        (inputApkSigningBlockOffset != -1)
                                ? inputApkSigningBlockOffset
                                : inputZipSections.getZipCentralDirectoryOffset());
        DataSource zipCentralDirectory = new ByteBufferDataSource(getZipCentralDirectory(inputApk, inputZipSections));
        DataSource zipEocd = new ByteBufferDataSource(inputZipSections.getZipEndOfCentralDirectory());

        // Step 2. Parse the input APK's ZIP Central Directory
        ByteBuffer inputCd = getZipCentralDirectory(inputApk, inputZipSections);
        List<CentralDirectoryRecord> inputCdRecords =
                parseZipCentralDirectory(inputCd, inputZipSections);

        // Step 3. Obtain a signer engine instance
        ApkSignerEngine signerEngine;
        if (mSignerEngine != null) {
            // Use the provided signer engine
            signerEngine = mSignerEngine;
        } else {
            // Construct a signer engine from the provided parameters
            int minSdkVersion;
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, zipEntries);
            }
            List<DefaultApkSignerEngine.SignerConfig> engineSignerConfigs =
                    new ArrayList<>(mSignerConfigs.size());
            for (SignerConfig signerConfig : mSignerConfigs) {
                engineSignerConfigs.add(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                signerConfig.getName(),
                                signerConfig.getPrivateKey(),
                                signerConfig.getCertificates())
                                .build());
            }
            DefaultApkSignerEngine.Builder signerEngineBuilder =
                    new DefaultApkSignerEngine.Builder(engineSignerConfigs, minSdkVersion, mSignerConfigsDisable)
                            .setV1SigningEnabled(mV1SigningEnabled)
                            .setV2SigningEnabled(mV2SigningEnabled)
                            .setV3SigningEnabled(mV3SigningEnabled)
                            .setVerityEnabled(mVerityEnabled)
                            .setDebuggableApkPermitted(mDebuggableApkPermitted)
                            .setOtherSignersSignaturesPreserved(mOtherSignersSignaturesPreserved)
                            .setSigningCertificateLineage(mSigningCertificateLineage);
            if (mCreatedBy != null) {
                signerEngineBuilder.setCreatedBy(mCreatedBy);
            }
            if (mSourceStampSignerConfig != null) {
                signerEngineBuilder.setStampSignerConfig(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                mSourceStampSignerConfig.getName(),
                                mSourceStampSignerConfig.getPrivateKey(),
                                mSourceStampSignerConfig.getCertificates())
                                .build());
            }
            if (mSourceStampSigningCertificateLineage != null) {
                signerEngineBuilder.setSourceStampSigningCertificateLineage(
                        mSourceStampSigningCertificateLineage);
            }
            signerEngine = signerEngineBuilder.build();
        }

        // Step 4. Provide the signer engine with the input APK's APK Signing Block (if any)
        if (inputApkSigningBlock != null) {
            signerEngine.inputApkSigningBlock(inputApkSigningBlock);
        }

        // Step 11. Generate and output APK Signature Scheme v2 and/or v3 signatures and/or
        // SourceStamp signatures, if necessary.
        // This may insert an APK Signing Block just before the output's ZIP Central Directory
        ApkSignerEngine.OutputApkSigningBlockRequest2 outputApkSigningBlockRequest =
                signerEngine.addSignedContentDigestsV2V3Cafebazaar(
                        zipEntries,
                        apkSigningBlock);

        ByteBuffer outputEocd = inputZipSections.getZipEndOfCentralDirectory();
        zipEntries.feed(0, zipEntries.size(), outputApkOut);

        if (outputApkSigningBlockRequest != null) {
            int padding = outputApkSigningBlockRequest.getPaddingSizeBeforeApkSigningBlock();
            outputApkOut.consume(ByteBuffer.allocate(padding));
            byte[] outputApkSigningBlock = outputApkSigningBlockRequest.getApkSigningBlock();
            outputApkOut.consume(outputApkSigningBlock, 0, outputApkSigningBlock.length);
            ZipUtils.setZipEocdCentralDirectoryOffset(
                    outputEocd,
                    inputZipSections.getZipCentralDirectoryOffset() + padding + outputApkSigningBlock.length);
            outputApkSigningBlockRequest.done();
        }

        // Step 12. Output ZIP Central Directory and ZIP End of Central Directory
        zipCentralDirectory.feed(0, zipCentralDirectory.size(), outputApkOut);
        outputApkOut.consume(outputEocd);
        signerEngine.outputDone();
    }

    private List<BinaryFormat> loadInputBinFile() throws FileNotFoundException {
        List<BinaryFormat> binaryFormatGroup = new ArrayList<>();
        Scanner scanner = new Scanner(mInputBinFile);

        while (scanner.hasNextLine()) {
            BinaryFormat binaryFormatItem = new BinaryFormat(scanner.nextLine(), scanner.nextLine());
            binaryFormatGroup.add(binaryFormatItem);
        }

        scanner.close();

        return binaryFormatGroup;
    }

    private void saveOutputBinFile(List<BinaryFormat> binaryFormatGroup) throws IOException {
        PrintWriter printWriter = new PrintWriter(new FileWriter(mOutputBinFile));

        for (BinaryFormat binaryFormatItem : binaryFormatGroup) {
            printWriter.println(binaryFormatItem.identifier);
            printWriter.println(binaryFormatItem.content);
        }

        printWriter.close();
    }

    private ApkSignerEngine obtainSignerEngine(
            int minSdkVersion,
            boolean signerConfigsDisable,
            DigestAlgorithm v1ContentDigestAlgorithm,
            boolean v2SigningEnabled,
            boolean v3SigningEnabled)
            throws InvalidKeyException {
        ApkSignerEngine signerEngine;
        if (mSignerEngine != null) {
            // Use the provided signer engine
            signerEngine = mSignerEngine;
        } else {
            // Construct a signer engine from the provided parameters
            List<DefaultApkSignerEngine.SignerConfig> engineSignerConfigs =
                    new ArrayList<>(mSignerConfigs.size());
            for (SignerConfig signerConfig : mSignerConfigs) {
                engineSignerConfigs.add(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                signerConfig.getName(),
                                signerConfig.getPrivateKey(),
                                signerConfig.getCertificates())
                                .build());
            }
            DefaultApkSignerEngine.Builder signerEngineBuilder =
                    new DefaultApkSignerEngine.Builder(engineSignerConfigs, minSdkVersion, signerConfigsDisable)
                            .setV1SigningEnabled(mV1SigningEnabled)
                            .setV2SigningEnabled(v2SigningEnabled)
                            .setV3SigningEnabled(v3SigningEnabled)
                            .setVerityEnabled(mVerityEnabled)
                            .setDebuggableApkPermitted(mDebuggableApkPermitted)
                            .setOtherSignersSignaturesPreserved(mOtherSignersSignaturesPreserved)
                            .setSigningCertificateLineage(mSigningCertificateLineage)
                            .setV1ContentDigestAlgorithm(v1ContentDigestAlgorithm);
            if (mCreatedBy != null) {
                signerEngineBuilder.setCreatedBy(mCreatedBy);
            }
            if (mSourceStampSignerConfig != null) {
                signerEngineBuilder.setStampSignerConfig(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                mSourceStampSignerConfig.getName(),
                                mSourceStampSignerConfig.getPrivateKey(),
                                mSourceStampSignerConfig.getCertificates())
                                .build());
            }
            if (mSourceStampSigningCertificateLineage != null) {
                signerEngineBuilder.setSourceStampSigningCertificateLineage(
                        mSourceStampSigningCertificateLineage);
            }
            signerEngine = signerEngineBuilder.build();
        }
        return signerEngine;
    }

    /**
     * Signs the input APK and outputs the resulting signed APK. The input APK is not modified.
     *
     * @throws IOException              if an I/O error is encountered while reading or writing the APKs
     * @throws ApkFormatException       if the input APK is malformed
     * @throws NoSuchAlgorithmException if the APK signatures cannot be produced or verified because
     *                                  a required cryptographic algorithm implementation is missing
     * @throws InvalidKeyException      if a signature could not be generated because a signing key is
     *                                  not suitable for generating the signature
     * @throws SignatureException       if an error occurred while generating or verifying a signature
     * @throws IllegalStateException    if this signer's configuration is missing required information
     *                                  or if the signing engine is in an invalid state.
     */
    public void sign()
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IllegalStateException {
        Closeable in = null;
        DataSource inputApk;
        try {
            if (mInputApkDataSource != null) {
                inputApk = mInputApkDataSource;
            } else if (mInputApkFile != null) {
                RandomAccessFile inputFile = new RandomAccessFile(mInputApkFile, "r");
                in = inputFile;
                inputApk = DataSources.asDataSource(inputFile);
            } else {
                throw new IllegalStateException("Input APK not specified");
            }

            Closeable out = null;
            try {
                DataSink outputApkOut;
                DataSource outputApkIn;
                if (mOutputApkDataSink != null) {
                    outputApkOut = mOutputApkDataSink;
                    outputApkIn = mOutputApkDataSource;
                } else if (mOutputApkFile != null) {
                    RandomAccessFile outputFile = new RandomAccessFile(mOutputApkFile, "rw");
                    out = outputFile;
                    outputFile.setLength(0);
                    outputApkOut = DataSinks.asDataSink(outputFile);
                    outputApkIn = DataSources.asDataSource(outputFile);
                } else {
                    throw new IllegalStateException("Output APK not specified");
                }

                sign(inputApk, outputApkOut, outputApkIn);
            } finally {
                if (out != null) {
                    out.close();
                }
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private void sign(DataSource inputApk, DataSink outputApkOut, DataSource outputApkIn)
            throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        // Step 1. Find input APK's main ZIP sections
        ApkUtils.ZipSections inputZipSections;
        try {
            inputZipSections = ApkUtils.findZipSections(inputApk);
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed APK: not a ZIP archive", e);
        }
        long inputApkSigningBlockOffset = -1;
        DataSource inputApkSigningBlock = null;
        try {
            ApkUtils.ApkSigningBlock apkSigningBlockInfo =
                    ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
            inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
            inputApkSigningBlock = apkSigningBlockInfo.getContents();
        } catch (ApkSigningBlockNotFoundException e) {
            // Input APK does not contain an APK Signing Block. That's OK. APKs are not required to
            // contain this block. It's only needed if the APK is signed using APK Signature Scheme
            // v2 and/or v3.
        }
        DataSource inputApkLfhSection =
                inputApk.slice(
                        0,
                        (inputApkSigningBlockOffset != -1)
                                ? inputApkSigningBlockOffset
                                : inputZipSections.getZipCentralDirectoryOffset());

        // Step 2. Parse the input APK's ZIP Central Directory
        ByteBuffer inputCd = getZipCentralDirectory(inputApk, inputZipSections);
        List<CentralDirectoryRecord> inputCdRecords =
                parseZipCentralDirectory(inputCd, inputZipSections);

        List<Hints.PatternWithRange> pinPatterns =
                extractPinPatterns(inputCdRecords, inputApkLfhSection);
        List<Hints.ByteRange> pinByteRanges = pinPatterns == null ? null : new ArrayList<>();

        // Step 3. Obtain a signer engine instance
        ApkSignerEngine signerEngine;
        if (mSignerEngine != null) {
            // Use the provided signer engine
            signerEngine = mSignerEngine;
        } else {
            // Construct a signer engine from the provided parameters
            int minSdkVersion;
            if (mMinSdkVersion != null) {
                // No need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = mMinSdkVersion;
            } else {
                // Need to extract minSdkVersion from the APK's AndroidManifest.xml
                minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, inputApkLfhSection);
            }
            List<DefaultApkSignerEngine.SignerConfig> engineSignerConfigs =
                    new ArrayList<>(mSignerConfigs.size());
            for (SignerConfig signerConfig : mSignerConfigs) {
                engineSignerConfigs.add(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                signerConfig.getName(),
                                signerConfig.getPrivateKey(),
                                signerConfig.getCertificates())
                                .build());
            }
            DefaultApkSignerEngine.Builder signerEngineBuilder =
                    new DefaultApkSignerEngine.Builder(engineSignerConfigs, minSdkVersion)
                            .setV1SigningEnabled(mV1SigningEnabled)
                            .setV2SigningEnabled(mV2SigningEnabled)
                            .setV3SigningEnabled(mV3SigningEnabled)
                            .setVerityEnabled(mVerityEnabled)
                            .setDebuggableApkPermitted(mDebuggableApkPermitted)
                            .setOtherSignersSignaturesPreserved(mOtherSignersSignaturesPreserved)
                            .setSigningCertificateLineage(mSigningCertificateLineage);
            if (mCreatedBy != null) {
                signerEngineBuilder.setCreatedBy(mCreatedBy);
            }
            if (mSourceStampSignerConfig != null) {
                signerEngineBuilder.setStampSignerConfig(
                        new DefaultApkSignerEngine.SignerConfig.Builder(
                                mSourceStampSignerConfig.getName(),
                                mSourceStampSignerConfig.getPrivateKey(),
                                mSourceStampSignerConfig.getCertificates())
                                .build());
            }
            if (mSourceStampSigningCertificateLineage != null) {
                signerEngineBuilder.setSourceStampSigningCertificateLineage(
                        mSourceStampSigningCertificateLineage);
            }
            signerEngine = signerEngineBuilder.build();
        }

        // Step 4. Provide the signer engine with the input APK's APK Signing Block (if any)
        if (inputApkSigningBlock != null) {
            signerEngine.inputApkSigningBlock(inputApkSigningBlock);
        }

        // Step 5. Iterate over input APK's entries and output the Local File Header + data of those
        // entries which need to be output. Entries are iterated in the order in which their Local
        // File Header records are stored in the file. This is to achieve better data locality in
        // case Central Directory entries are in the wrong order.
        List<CentralDirectoryRecord> inputCdRecordsSortedByLfhOffset =
                new ArrayList<>(inputCdRecords);
        Collections.sort(
                inputCdRecordsSortedByLfhOffset,
                CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
        int lastModifiedDateForNewEntries = -1;
        int lastModifiedTimeForNewEntries = -1;
        long inputOffset = 0;
        long outputOffset = 0;
        byte[] sourceStampCertificateDigest = null;
        Map<String, CentralDirectoryRecord> outputCdRecordsByName =
                new HashMap<>(inputCdRecords.size());
        for (final CentralDirectoryRecord inputCdRecord : inputCdRecordsSortedByLfhOffset) {
            String entryName = inputCdRecord.getName();
            if (Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME.equals(entryName)) {
                continue; // We'll re-add below if needed.
            }
            if (SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME.equals(entryName)) {
                try {
                    sourceStampCertificateDigest =
                            LocalFileRecord.getUncompressedData(
                                    inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                } catch (ZipFormatException ex) {
                    throw new ApkFormatException("Bad source stamp entry");
                }
                continue; // Existing source stamp is handled below as needed.
            }
            ApkSignerEngine.InputJarEntryInstructions entryInstructions =
                    signerEngine.inputJarEntry(entryName);
            boolean shouldOutput;
            switch (entryInstructions.getOutputPolicy()) {
                case OUTPUT:
                    shouldOutput = true;
                    break;
                case OUTPUT_BY_ENGINE:
                case SKIP:
                    shouldOutput = false;
                    break;
                default:
                    throw new RuntimeException(
                            "Unknown output policy: " + entryInstructions.getOutputPolicy());
            }

            long inputLocalFileHeaderStartOffset = inputCdRecord.getLocalFileHeaderOffset();
            if (inputLocalFileHeaderStartOffset > inputOffset) {
                // Unprocessed data in input starting at inputOffset and ending and the start of
                // this record's LFH. We output this data verbatim because this signer is supposed
                // to preserve as much of input as possible.
                long chunkSize = inputLocalFileHeaderStartOffset - inputOffset;
                inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
                outputOffset += chunkSize;
                inputOffset = inputLocalFileHeaderStartOffset;
            }
            LocalFileRecord inputLocalFileRecord;
            try {
                inputLocalFileRecord =
                        LocalFileRecord.getRecord(
                                inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed ZIP entry: " + inputCdRecord.getName(), e);
            }
            inputOffset += inputLocalFileRecord.getSize();

            ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest =
                    entryInstructions.getInspectJarEntryRequest();
            if (inspectEntryRequest != null) {
                fulfillInspectInputJarEntryRequest(
                        inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
            }

            if (shouldOutput) {
                // Find the max value of last modified, to be used for new entries added by the
                // signer.
                int lastModifiedDate = inputCdRecord.getLastModificationDate();
                int lastModifiedTime = inputCdRecord.getLastModificationTime();
                if ((lastModifiedDateForNewEntries == -1)
                        || (lastModifiedDate > lastModifiedDateForNewEntries)
                        || ((lastModifiedDate == lastModifiedDateForNewEntries)
                        && (lastModifiedTime > lastModifiedTimeForNewEntries))) {
                    lastModifiedDateForNewEntries = lastModifiedDate;
                    lastModifiedTimeForNewEntries = lastModifiedTime;
                }

                inspectEntryRequest = signerEngine.outputJarEntry(entryName);
                if (inspectEntryRequest != null) {
                    fulfillInspectInputJarEntryRequest(
                            inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                }

                // Output entry's Local File Header + data
                long outputLocalFileHeaderOffset = outputOffset;
                OutputSizeAndDataOffset outputLfrResult =
                        outputInputJarEntryLfhRecordPreservingDataAlignment(
                                inputApkLfhSection,
                                inputLocalFileRecord,
                                outputApkOut,
                                outputLocalFileHeaderOffset);
                outputOffset += outputLfrResult.outputBytes;
                long outputDataOffset =
                        outputLocalFileHeaderOffset + outputLfrResult.dataOffsetBytes;

                if (pinPatterns != null) {
                    boolean pinFileHeader = false;
                    for (Hints.PatternWithRange pinPattern : pinPatterns) {
                        if (pinPattern.matcher(inputCdRecord.getName()).matches()) {
                            Hints.ByteRange dataRange =
                                    new Hints.ByteRange(outputDataOffset, outputOffset);
                            Hints.ByteRange pinRange =
                                    pinPattern.ClampToAbsoluteByteRange(dataRange);
                            if (pinRange != null) {
                                pinFileHeader = true;
                                pinByteRanges.add(pinRange);
                            }
                        }
                    }
                    if (pinFileHeader) {
                        pinByteRanges.add(
                                new Hints.ByteRange(outputLocalFileHeaderOffset, outputDataOffset));
                    }
                }

                // Enqueue entry's Central Directory record for output
                CentralDirectoryRecord outputCdRecord;
                if (outputLocalFileHeaderOffset == inputLocalFileRecord.getStartOffsetInArchive()) {
                    outputCdRecord = inputCdRecord;
                } else {
                    outputCdRecord =
                            inputCdRecord.createWithModifiedLocalFileHeaderOffset(
                                    outputLocalFileHeaderOffset);
                }
                outputCdRecordsByName.put(entryName, outputCdRecord);
            }
        }
        long inputLfhSectionSize = inputApkLfhSection.size();
        if (inputOffset < inputLfhSectionSize) {
            // Unprocessed data in input starting at inputOffset and ending and the end of the input
            // APK's LFH section. We output this data verbatim because this signer is supposed
            // to preserve as much of input as possible.
            long chunkSize = inputLfhSectionSize - inputOffset;
            inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
            outputOffset += chunkSize;
            inputOffset = inputLfhSectionSize;
        }

        // Step 6. Sort output APK's Central Directory records in the order in which they should
        // appear in the output
        List<CentralDirectoryRecord> outputCdRecords = new ArrayList<>(inputCdRecords.size() + 10);
        for (CentralDirectoryRecord inputCdRecord : inputCdRecords) {
            String entryName = inputCdRecord.getName();
            CentralDirectoryRecord outputCdRecord = outputCdRecordsByName.get(entryName);
            if (outputCdRecord != null) {
                outputCdRecords.add(outputCdRecord);
            }
        }

        if (lastModifiedDateForNewEntries == -1) {
            lastModifiedDateForNewEntries = 0x3a21; // Jan 1 2009 (DOS)
            lastModifiedTimeForNewEntries = 0;
        }

        // Step 7. Generate and output SourceStamp certificate hash, if necessary. This may output
        // more Local File Header + data entries and add to the list of output Central Directory
        // records.
        if (signerEngine.isEligibleForSourceStamp()) {
            byte[] uncompressedData = signerEngine.generateSourceStampCertificateDigest();
            if (mForceSourceStampOverwrite
                    || sourceStampCertificateDigest == null
                    || Arrays.equals(uncompressedData, sourceStampCertificateDigest)) {
                outputOffset +=
                        outputDataToOutputApk(
                                SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME,
                                uncompressedData,
                                outputOffset,
                                outputCdRecords,
                                lastModifiedTimeForNewEntries,
                                lastModifiedDateForNewEntries,
                                outputApkOut);
            } else {
                throw new ApkFormatException(
                        String.format(
                                "Cannot generate SourceStamp. APK contains an existing entry with"
                                        + " the name: %s, and it is different than the provided source"
                                        + " stamp certificate",
                                SOURCE_STAMP_CERTIFICATE_HASH_ZIP_ENTRY_NAME));
            }
        }

        // Step 8. Generate and output JAR signatures, if necessary. This may output more Local File
        // Header + data entries and add to the list of output Central Directory records.
        ApkSignerEngine.OutputJarSignatureRequest outputJarSignatureRequest =
                signerEngine.outputJarEntries();
        if (outputJarSignatureRequest != null) {
            for (ApkSignerEngine.OutputJarSignatureRequest.JarEntry entry :
                    outputJarSignatureRequest.getAdditionalJarEntries()) {
                String entryName = entry.getName();
                byte[] uncompressedData = entry.getData();

                ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest =
                        signerEngine.outputJarEntry(entryName);
                if (inspectEntryRequest != null) {
                    inspectEntryRequest
                            .getDataSink()
                            .consume(uncompressedData, 0, uncompressedData.length);
                    inspectEntryRequest.done();
                }

                outputOffset +=
                        outputDataToOutputApk(
                                entryName,
                                uncompressedData,
                                outputOffset,
                                outputCdRecords,
                                lastModifiedTimeForNewEntries,
                                lastModifiedDateForNewEntries,
                                outputApkOut);
            }
            outputJarSignatureRequest.done();
        }

        if (pinByteRanges != null) {
            pinByteRanges.add(new Hints.ByteRange(outputOffset, Long.MAX_VALUE)); // central dir
            String entryName = Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME;
            byte[] uncompressedData = Hints.encodeByteRangeList(pinByteRanges);
            outputOffset +=
                    outputDataToOutputApk(
                            entryName,
                            uncompressedData,
                            outputOffset,
                            outputCdRecords,
                            lastModifiedTimeForNewEntries,
                            lastModifiedDateForNewEntries,
                            outputApkOut);
        }

        // Step 9. Construct output ZIP Central Directory in an in-memory buffer
        long outputCentralDirSizeBytes = 0;
        for (CentralDirectoryRecord record : outputCdRecords) {
            outputCentralDirSizeBytes += record.getSize();
        }
        if (outputCentralDirSizeBytes > Integer.MAX_VALUE) {
            throw new IOException(
                    "Output ZIP Central Directory too large: "
                            + outputCentralDirSizeBytes
                            + " bytes");
        }
        ByteBuffer outputCentralDir = ByteBuffer.allocate((int) outputCentralDirSizeBytes);
        for (CentralDirectoryRecord record : outputCdRecords) {
            record.copyTo(outputCentralDir);
        }
        outputCentralDir.flip();
        DataSource outputCentralDirDataSource = new ByteBufferDataSource(outputCentralDir);
        long outputCentralDirStartOffset = outputOffset;
        int outputCentralDirRecordCount = outputCdRecords.size();

        // Step 10. Construct output ZIP End of Central Directory record in an in-memory buffer
        ByteBuffer outputEocd =
                EocdRecord.createWithModifiedCentralDirectoryInfo(
                        inputZipSections.getZipEndOfCentralDirectory(),
                        outputCentralDirRecordCount,
                        outputCentralDirDataSource.size(),
                        outputCentralDirStartOffset);

        // Step 11. Generate and output APK Signature Scheme v2 and/or v3 signatures and/or
        // SourceStamp signatures, if necessary.
        // This may insert an APK Signing Block just before the output's ZIP Central Directory
        ApkSignerEngine.OutputApkSigningBlockRequest2 outputApkSigningBlockRequest =
                signerEngine.outputZipSections2(
                        outputApkIn,
                        outputCentralDirDataSource,
                        DataSources.asDataSource(outputEocd));

        if (outputApkSigningBlockRequest != null) {
            int padding = outputApkSigningBlockRequest.getPaddingSizeBeforeApkSigningBlock();
            outputApkOut.consume(ByteBuffer.allocate(padding));
            byte[] outputApkSigningBlock = outputApkSigningBlockRequest.getApkSigningBlock();
            outputApkOut.consume(outputApkSigningBlock, 0, outputApkSigningBlock.length);
            ZipUtils.setZipEocdCentralDirectoryOffset(
                    outputEocd,
                    outputCentralDirStartOffset + padding + outputApkSigningBlock.length);
            outputApkSigningBlockRequest.done();
        }

        // Step 12. Output ZIP Central Directory and ZIP End of Central Directory
        outputCentralDirDataSource.feed(0, outputCentralDirDataSource.size(), outputApkOut);
        outputApkOut.consume(outputEocd);
        signerEngine.outputDone();

        // Step 13. Generate and output APK Signature Scheme v4 signatures, if necessary.
        if (mV4SigningEnabled) {
            signerEngine.signV4(outputApkIn, mOutputV4File, !mV4ErrorReportingEnabled);
        }
    }

    private static long outputDataToOutputApk(
            String entryName,
            byte[] uncompressedData,
            long localFileHeaderOffset,
            List<CentralDirectoryRecord> outputCdRecords,
            int lastModifiedTimeForNewEntries,
            int lastModifiedDateForNewEntries,
            DataSink outputApkOut)
            throws IOException {
        ZipUtils.DeflateResult deflateResult = ZipUtils.deflate(ByteBuffer.wrap(uncompressedData));
        byte[] compressedData = deflateResult.output;
        long uncompressedDataCrc32 = deflateResult.inputCrc32;
        long numOfDataBytes =
                LocalFileRecord.outputRecordWithDeflateCompressedData(
                        entryName,
                        lastModifiedTimeForNewEntries,
                        lastModifiedDateForNewEntries,
                        compressedData,
                        uncompressedDataCrc32,
                        uncompressedData.length,
                        outputApkOut);
        outputCdRecords.add(
                CentralDirectoryRecord.createWithDeflateCompressedData(
                        entryName,
                        lastModifiedTimeForNewEntries,
                        lastModifiedDateForNewEntries,
                        uncompressedDataCrc32,
                        compressedData.length,
                        uncompressedData.length,
                        localFileHeaderOffset));
        return numOfDataBytes;
    }

    private static void fulfillInspectInputJarEntryRequest(
            DataSource lfhSection,
            LocalFileRecord localFileRecord,
            ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest)
            throws IOException, ApkFormatException {
        try {
            localFileRecord.outputUncompressedData(lfhSection, inspectEntryRequest.getDataSink());
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed ZIP entry: " + localFileRecord.getName(), e);
        }
        inspectEntryRequest.done();
    }

    private static class OutputSizeAndDataOffset {
        public long outputBytes;
        public long dataOffsetBytes;

        public OutputSizeAndDataOffset(long outputBytes, long dataOffsetBytes) {
            this.outputBytes = outputBytes;
            this.dataOffsetBytes = dataOffsetBytes;
        }
    }

    private static OutputSizeAndDataOffset outputInputJarEntryLfhRecordPreservingDataAlignment(
            DataSource inputLfhSection,
            LocalFileRecord inputRecord,
            DataSink outputLfhSection,
            long outputOffset)
            throws IOException {
        long inputOffset = inputRecord.getStartOffsetInArchive();
        if (inputOffset == outputOffset) {
            // This record's data will be aligned same as in the input APK.
            return new OutputSizeAndDataOffset(
                    inputRecord.outputRecord(inputLfhSection, outputLfhSection),
                    inputRecord.getDataStartOffsetInRecord());
        }
        int dataAlignmentMultiple = getInputJarEntryDataAlignmentMultiple(inputRecord);
        if ((dataAlignmentMultiple <= 1)
                || ((inputOffset % dataAlignmentMultiple)
                == (outputOffset % dataAlignmentMultiple))) {
            // This record's data will be aligned same as in the input APK.
            return new OutputSizeAndDataOffset(
                    inputRecord.outputRecord(inputLfhSection, outputLfhSection),
                    inputRecord.getDataStartOffsetInRecord());
        }

        long inputDataStartOffset = inputOffset + inputRecord.getDataStartOffsetInRecord();
        if ((inputDataStartOffset % dataAlignmentMultiple) != 0) {
            // This record's data is not aligned in the input APK. No need to align it in the
            // output.
            return new OutputSizeAndDataOffset(
                    inputRecord.outputRecord(inputLfhSection, outputLfhSection),
                    inputRecord.getDataStartOffsetInRecord());
        }

        // This record's data needs to be re-aligned in the output. This is achieved using the
        // record's extra field.
        ByteBuffer aligningExtra =
                createExtraFieldToAlignData(
                        inputRecord.getExtra(),
                        outputOffset + inputRecord.getExtraFieldStartOffsetInsideRecord(),
                        dataAlignmentMultiple);
        long dataOffset =
                (long) inputRecord.getDataStartOffsetInRecord()
                        + aligningExtra.remaining()
                        - inputRecord.getExtra().remaining();
        return new OutputSizeAndDataOffset(
                inputRecord.outputRecordWithModifiedExtra(
                        inputLfhSection, aligningExtra, outputLfhSection),
                dataOffset);
    }

    private static int getInputJarEntryDataAlignmentMultiple(LocalFileRecord entry) {
        if (entry.isDataCompressed()) {
            // Compressed entries don't need to be aligned
            return 1;
        }

        // Attempt to obtain the alignment multiple from the entry's extra field.
        ByteBuffer extra = entry.getExtra();
        if (extra.hasRemaining()) {
            extra.order(ByteOrder.LITTLE_ENDIAN);
            // FORMAT: sequence of fields. Each field consists of:
            //   * uint16 ID
            //   * uint16 size
            //   * 'size' bytes: payload
            while (extra.remaining() >= 4) {
                short headerId = extra.getShort();
                int dataSize = ZipUtils.getUnsignedInt16(extra);
                if (dataSize > extra.remaining()) {
                    // Malformed field -- insufficient input remaining
                    break;
                }
                if (headerId != ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID) {
                    // Skip this field
                    extra.position(extra.position() + dataSize);
                    continue;
                }
                // This is APK alignment field.
                // FORMAT:
                //  * uint16 alignment multiple (in bytes)
                //  * remaining bytes -- padding to achieve alignment of data which starts after
                //    the extra field
                if (dataSize < 2) {
                    // Malformed
                    break;
                }
                return ZipUtils.getUnsignedInt16(extra);
            }
        }

        // Fall back to filename-based defaults
        return (entry.getName().endsWith(".so")) ? ANDROID_COMMON_PAGE_ALIGNMENT_BYTES : 4;
    }

    private static ByteBuffer createExtraFieldToAlignData(
            ByteBuffer original, long extraStartOffset, int dataAlignmentMultiple) {
        if (dataAlignmentMultiple <= 1) {
            return original;
        }

        // In the worst case scenario, we'll increase the output size by 6 + dataAlignment - 1.
        ByteBuffer result = ByteBuffer.allocate(original.remaining() + 5 + dataAlignmentMultiple);
        result.order(ByteOrder.LITTLE_ENDIAN);

        // Step 1. Output all extra fields other than the one which is to do with alignment
        // FORMAT: sequence of fields. Each field consists of:
        //   * uint16 ID
        //   * uint16 size
        //   * 'size' bytes: payload
        while (original.remaining() >= 4) {
            short headerId = original.getShort();
            int dataSize = ZipUtils.getUnsignedInt16(original);
            if (dataSize > original.remaining()) {
                // Malformed field -- insufficient input remaining
                break;
            }
            if (((headerId == 0) && (dataSize == 0))
                    || (headerId == ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID)) {
                // Ignore the field if it has to do with the old APK data alignment method (filling
                // the extra field with 0x00 bytes) or the new APK data alignment method.
                original.position(original.position() + dataSize);
                continue;
            }
            // Copy this field (including header) to the output
            original.position(original.position() - 4);
            int originalLimit = original.limit();
            original.limit(original.position() + 4 + dataSize);
            result.put(original);
            original.limit(originalLimit);
        }

        // Step 2. Add alignment field
        // FORMAT:
        //  * uint16 extra header ID
        //  * uint16 extra data size
        //        Payload ('data size' bytes)
        //      * uint16 alignment multiple (in bytes)
        //      * remaining bytes -- padding to achieve alignment of data which starts after the
        //        extra field
        long dataMinStartOffset =
                extraStartOffset
                        + result.position()
                        + ALIGNMENT_ZIP_EXTRA_DATA_FIELD_MIN_SIZE_BYTES;
        int paddingSizeBytes =
                (dataAlignmentMultiple - ((int) (dataMinStartOffset % dataAlignmentMultiple)))
                        % dataAlignmentMultiple;
        result.putShort(ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID);
        ZipUtils.putUnsignedInt16(result, 2 + paddingSizeBytes);
        ZipUtils.putUnsignedInt16(result, dataAlignmentMultiple);
        result.position(result.position() + paddingSizeBytes);
        result.flip();

        return result;
    }

    private static ByteBuffer getZipCentralDirectory(
            DataSource apk, ApkUtils.ZipSections apkSections)
            throws IOException, ApkFormatException {
        long cdSizeBytes = apkSections.getZipCentralDirectorySizeBytes();
        if (cdSizeBytes > Integer.MAX_VALUE) {
            throw new ApkFormatException("ZIP Central Directory too large: " + cdSizeBytes);
        }
        long cdOffset = apkSections.getZipCentralDirectoryOffset();
        ByteBuffer cd = apk.getByteBuffer(cdOffset, (int) cdSizeBytes);
        cd.order(ByteOrder.LITTLE_ENDIAN);
        return cd;
    }

    private static List<CentralDirectoryRecord> parseZipCentralDirectory(
            ByteBuffer cd, ApkUtils.ZipSections apkSections) throws ApkFormatException {
        long cdOffset = apkSections.getZipCentralDirectoryOffset();
        int expectedCdRecordCount = apkSections.getZipCentralDirectoryRecordCount();
        List<CentralDirectoryRecord> cdRecords = new ArrayList<>(expectedCdRecordCount);
        Set<String> entryNames = new HashSet<>(expectedCdRecordCount);
        for (int i = 0; i < expectedCdRecordCount; i++) {
            CentralDirectoryRecord cdRecord;
            int offsetInsideCd = cd.position();
            try {
                cdRecord = CentralDirectoryRecord.getRecord(cd);
            } catch (ZipFormatException e) {
                throw new ApkFormatException(
                        "Malformed ZIP Central Directory record #"
                                + (i + 1)
                                + " at file offset "
                                + (cdOffset + offsetInsideCd),
                        e);
            }
            String entryName = cdRecord.getName();
            if (!entryNames.add(entryName)) {
                throw new ApkFormatException(
                        "Multiple ZIP entries with the same name: " + entryName);
            }
            cdRecords.add(cdRecord);
        }
        if (cd.hasRemaining()) {
            throw new ApkFormatException(
                    "Unused space at the end of ZIP Central Directory: "
                            + cd.remaining()
                            + " bytes starting at file offset "
                            + (cdOffset + cd.position()));
        }

        return cdRecords;
    }

    private static CentralDirectoryRecord findCdRecord(
            List<CentralDirectoryRecord> cdRecords, String name) {
        for (CentralDirectoryRecord cdRecord : cdRecords) {
            if (name.equals(cdRecord.getName())) {
                return cdRecord;
            }
        }
        return null;
    }

    /**
     * Returns the contents of the APK's {@code AndroidManifest.xml} or {@code null} if this entry
     * is not present in the APK.
     */
    static ByteBuffer getAndroidManifestFromApk(
            List<CentralDirectoryRecord> cdRecords, DataSource lhfSection)
            throws IOException, ApkFormatException, ZipFormatException {
        CentralDirectoryRecord androidManifestCdRecord =
                findCdRecord(cdRecords, ANDROID_MANIFEST_ZIP_ENTRY_NAME);
        if (androidManifestCdRecord == null) {
            throw new ApkFormatException("Missing " + ANDROID_MANIFEST_ZIP_ENTRY_NAME);
        }

        return ByteBuffer.wrap(
                LocalFileRecord.getUncompressedData(
                        lhfSection, androidManifestCdRecord, lhfSection.size()));
    }

    /**
     * Return list of pin patterns embedded in the pin pattern asset file. If no such file, return
     * {@code null}.
     */
    private static List<Hints.PatternWithRange> extractPinPatterns(
            List<CentralDirectoryRecord> cdRecords, DataSource lhfSection)
            throws IOException, ApkFormatException {
        CentralDirectoryRecord pinListCdRecord =
                findCdRecord(cdRecords, Hints.PIN_HINT_ASSET_ZIP_ENTRY_NAME);
        List<Hints.PatternWithRange> pinPatterns = null;
        if (pinListCdRecord != null) {
            pinPatterns = new ArrayList<>();
            byte[] patternBlob;
            try {
                patternBlob =
                        LocalFileRecord.getUncompressedData(
                                lhfSection, pinListCdRecord, lhfSection.size());
            } catch (ZipFormatException ex) {
                throw new ApkFormatException("Bad " + pinListCdRecord);
            }
            pinPatterns = Hints.parsePinPatterns(patternBlob);
        }
        return pinPatterns;
    }

    /**
     * Returns the minimum Android version (API Level) supported by the provided APK. This is based
     * on the {@code android:minSdkVersion} attributes of the APK's {@code AndroidManifest.xml}.
     */
    private static int getMinSdkVersionFromApk(
            List<CentralDirectoryRecord> cdRecords, DataSource lhfSection)
            throws IOException, MinSdkVersionException {
        ByteBuffer androidManifest;
        try {
            androidManifest = getAndroidManifestFromApk(cdRecords, lhfSection);
        } catch (ZipFormatException | ApkFormatException e) {
            throw new MinSdkVersionException(
                    "Failed to determine APK's minimum supported Android platform version", e);
        }
        return ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(androidManifest);
    }

    /**
     * Configuration of a signer.
     *
     * <p>Use {@link Builder} to obtain configuration instances.
     */
    public static class SignerConfig {
        private final String mName;
        private final PrivateKey mPrivateKey;
        private final List<X509Certificate> mCertificates;

        private SignerConfig(
                String name, PrivateKey privateKey, List<X509Certificate> certificates) {
            mName = name;
            mPrivateKey = privateKey;
            mCertificates = Collections.unmodifiableList(new ArrayList<>(certificates));
        }

        /**
         * Returns the name of this signer.
         */
        public String getName() {
            return mName;
        }

        /**
         * Returns the signing key of this signer.
         */
        public PrivateKey getPrivateKey() {
            return mPrivateKey;
        }

        /**
         * Returns the certificate(s) of this signer. The first certificate's public key corresponds
         * to this signer's private key.
         */
        public List<X509Certificate> getCertificates() {
            return mCertificates;
        }

        /**
         * Builder of {@link SignerConfig} instances.
         */
        public static class Builder {
            private final String mName;
            private final PrivateKey mPrivateKey;
            private final List<X509Certificate> mCertificates;

            /**
             * Constructs a new {@code Builder}.
             *
             * @param name         signer's name. The name is reflected in the name of files comprising the
             *                     JAR signature of the APK.
             * @param privateKey   signing key
             * @param certificates list of one or more X.509 certificates. The subject public key of
             *                     the first certificate must correspond to the {@code privateKey}.
             */
            public Builder(String name, PrivateKey privateKey, List<X509Certificate> certificates) {
                if (name.isEmpty()) {
                    throw new IllegalArgumentException("Empty name");
                }
                mName = name;
                mPrivateKey = privateKey;
                mCertificates = new ArrayList<>(certificates);
            }

            /**
             * Returns a new {@code SignerConfig} instance configured based on the configuration of
             * this builder.
             */
            public SignerConfig build() {
                return new SignerConfig(mName, mPrivateKey, mCertificates);
            }
        }
    }

    /**
     * Builder of {@link ApkSigner} instances.
     *
     * <p>The builder requires the following information to construct a working {@code ApkSigner}:
     *
     * <ul>
     *   <li>Signer configs or {@link ApkSignerEngine} -- provided in the constructor,
     *   <li>APK to be signed -- see {@link #setInputApk(File) setInputApk} variants,
     *   <li>where to store the output signed APK -- see {@link #setOutputApk(File) setOutputApk}
     *       variants.
     * </ul>
     */
    public static class Builder {
        private final List<SignerConfig> mSignerConfigs;
        private SignerConfig mSourceStampSignerConfig;
        private SigningCertificateLineage mSourceStampSigningCertificateLineage;
        private boolean mForceSourceStampOverwrite = false;
        private boolean mV1SigningEnabled = true;
        private boolean mV2SigningEnabled = true;
        private boolean mV3SigningEnabled = true;
        private boolean mV4SigningEnabled = true;
        private boolean mVerityEnabled = false;
        private boolean mV4ErrorReportingEnabled = false;
        private boolean mDebuggableApkPermitted = true;
        private boolean mOtherSignersSignaturesPreserved;
        private boolean mSignerConfigsDisable = false;
        private String mCreatedBy;
        private Integer mMinSdkVersion;

        private final ApkSignerEngine mSignerEngine;

        private File mInputApkFile;
        private DataSource mInputApkDataSource;

        private File mOutputApkFile;
        private DataSink mOutputApkDataSink;
        private DataSource mOutputApkDataSource;

        private File mOutputV4File;

        private File mInputBinFile;
        private File mOutputBinFile;
        private List<BinaryFormat> binaryFormatItems;

        private SigningCertificateLineage mSigningCertificateLineage;

        // APK Signature Scheme v3 only supports a single signing certificate, so to move to v3
        // signing by default, but not require prior clients to update to explicitly disable v3
        // signing for multiple signers, we modify the mV3SigningEnabled depending on the provided
        // inputs (multiple signers and mSigningCertificateLineage in particular).  Maintain two
        // extra variables to record whether or not mV3SigningEnabled has been set directly by a
        // client and so should override the default behavior.
        private boolean mV3SigningExplicitlyDisabled = false;
        private boolean mV3SigningExplicitlyEnabled = false;

        /**
         * Constructs a new {@code Builder} for an {@code ApkSigner} which signs using the provided
         * signer configurations. The resulting signer may be further customized through this
         * builder's setters, such as {@link #setMinSdkVersion(int)}, {@link
         * #setV1SigningEnabled(boolean)}, {@link #setV2SigningEnabled(boolean)}, {@link
         * #setOtherSignersSignaturesPreserved(boolean)}, {@link #setCreatedBy(String)}.
         *
         * <p>{@link #Builder(ApkSignerEngine)} is an alternative for advanced use cases where more
         * control over low-level details of signing is desired.
         */
        public Builder(List<SignerConfig> signerConfigs) {
            if (signerConfigs.isEmpty()) {
                throw new IllegalArgumentException("At least one signer config must be provided");
            }
            if (signerConfigs.size() > 1) {
                // APK Signature Scheme v3 only supports single signer, unless a
                // SigningCertificateLineage is provided, in which case this will be reset to true,
                // since we don't yet have a v4 scheme about which to worry
                mV3SigningEnabled = false;
            }
            mSignerConfigs = new ArrayList<>(signerConfigs);
            mSignerEngine = null;
        }

        public Builder(List<SignerConfig> signerConfigs, boolean signerConfigsDisable) {
            if (signerConfigs.isEmpty() && !signerConfigsDisable) {
                throw new IllegalArgumentException("At least one signer config must be provided");
            }
            if (signerConfigs.size() > 1) {
                // APK Signature Scheme v3 only supports single signer, unless a
                // SigningCertificateLineage is provided, in which case this will be reset to true,
                // since we don't yet have a v4 scheme about which to worry
                mV3SigningEnabled = false;
            }
            mSignerConfigs = new ArrayList<>(signerConfigs);
            mSignerConfigsDisable = signerConfigsDisable;
            mSignerEngine = null;
        }

        /**
         * Constructs a new {@code Builder} for an {@code ApkSigner} which signs using the provided
         * signing engine. This is meant for advanced use cases where more control is needed over
         * the lower-level details of signing. For typical use cases, {@link #Builder(List)} is more
         * appropriate.
         */
        public Builder(ApkSignerEngine signerEngine) {
            if (signerEngine == null) {
                throw new NullPointerException("signerEngine == null");
            }
            mSignerEngine = signerEngine;
            mSignerConfigs = null;
        }

        /**
         * Sets the signing configuration of the source stamp to be embedded in the APK.
         */
        public Builder setSourceStampSignerConfig(SignerConfig sourceStampSignerConfig) {
            mSourceStampSignerConfig = sourceStampSignerConfig;
            return this;
        }

        /**
         * Sets the source stamp {@link SigningCertificateLineage}. This structure provides proof of
         * signing certificate rotation for certificates previously used to sign source stamps.
         */
        public Builder setSourceStampSigningCertificateLineage(
                SigningCertificateLineage sourceStampSigningCertificateLineage) {
            mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
            return this;
        }

        /**
         * Sets whether the APK should overwrite existing source stamp, if found.
         *
         * @param force {@code true} to require the APK to be overwrite existing source stamp
         */
        public Builder setForceSourceStampOverwrite(boolean force) {
            mForceSourceStampOverwrite = force;
            return this;
        }

        /**
         * Sets the APK to be signed.
         *
         * @see #setInputApk(DataSource)
         */
        public Builder setInputApk(File inputApk) {
            if (inputApk == null) {
                throw new NullPointerException("inputApk == null");
            }
            mInputApkFile = inputApk;
            mInputApkDataSource = null;
            return this;
        }

        /**
         * Sets the APK to be signed.
         *
         * @see #setInputApk(File)
         */
        public Builder setInputApk(DataSource inputApk) {
            if (inputApk == null) {
                throw new NullPointerException("inputApk == null");
            }
            mInputApkDataSource = inputApk;
            mInputApkFile = null;
            return this;
        }

        /**
         * Sets the location of the output (signed) APK. {@code ApkSigner} will create this file if
         * it doesn't exist.
         *
         * @see #setOutputApk(ReadableDataSink)
         * @see #setOutputApk(DataSink, DataSource)
         */
        public Builder setOutputApk(File outputApk) {
            if (outputApk == null) {
                throw new NullPointerException("outputApk == null");
            }
            mOutputApkFile = outputApk;
            mOutputApkDataSink = null;
            mOutputApkDataSource = null;
            return this;
        }

        /**
         * Sets the readable data sink which will receive the output (signed) APK. After signing,
         * the contents of the output APK will be available via the {@link DataSource} interface of
         * the sink.
         *
         * <p>This variant of {@code setOutputApk} is useful for avoiding writing the output APK to
         * a file. For example, an in-memory data sink, such as {@link
         * DataSinks#newInMemoryDataSink()}, could be used instead of a file.
         *
         * @see #setOutputApk(File)
         * @see #setOutputApk(DataSink, DataSource)
         */
        public Builder setOutputApk(ReadableDataSink outputApk) {
            if (outputApk == null) {
                throw new NullPointerException("outputApk == null");
            }
            return setOutputApk(outputApk, outputApk);
        }

        /**
         * Sets the sink which will receive the output (signed) APK. Data received by the {@code
         * outputApkOut} sink must be visible through the {@code outputApkIn} data source.
         *
         * <p>This is an advanced variant of {@link #setOutputApk(ReadableDataSink)}, enabling the
         * sink and the source to be different objects.
         *
         * @see #setOutputApk(ReadableDataSink)
         * @see #setOutputApk(File)
         */
        public Builder setOutputApk(DataSink outputApkOut, DataSource outputApkIn) {
            if (outputApkOut == null) {
                throw new NullPointerException("outputApkOut == null");
            }
            if (outputApkIn == null) {
                throw new NullPointerException("outputApkIn == null");
            }
            mOutputApkFile = null;
            mOutputApkDataSink = outputApkOut;
            mOutputApkDataSource = outputApkIn;
            return this;
        }

        public Builder setInputBin(File inputBin) {
            if (inputBin == null) {
                throw new NullPointerException("inputBin == null");
            }
            mInputBinFile = inputBin;
            return this;
        }

        public Builder setSignDigest(String identifier, String content){
            if (content == null){
                throw new NullPointerException("content == null");
            }
            BinaryFormat binaryFormatItem = new BinaryFormat(identifier, content);
            binaryFormatItems = new ArrayList<>();
            binaryFormatItems.add(binaryFormatItem);
            return this;
        }

        public Builder setOutputBin(File outputBin) {
            if (outputBin == null) {
                throw new NullPointerException("outputBin == null");
            }
            mOutputBinFile = outputBin;
            return this;
        }

        /**
         * Sets the location of the V4 output file. {@code ApkSigner} will create this file if it
         * doesn't exist.
         */
        public Builder setV4SignatureOutputFile(File v4SignatureOutputFile) {
            if (v4SignatureOutputFile == null) {
                throw new NullPointerException("v4HashRootOutputFile == null");
            }
            mOutputV4File = v4SignatureOutputFile;
            return this;
        }

        /**
         * Sets the minimum Android platform version (API Level) on which APK signatures produced by
         * the signer being built must verify. This method is useful for overriding the default
         * behavior where the minimum API Level is obtained from the {@code android:minSdkVersion}
         * attribute of the APK's {@code AndroidManifest.xml}.
         *
         * <p><em>Note:</em> This method may result in APK signatures which don't verify on some
         * Android platform versions supported by the APK.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         *
         * @throws IllegalStateException if this builder was initialized with an {@link
         *                               ApkSignerEngine}
         */
        public Builder setMinSdkVersion(int minSdkVersion) {
            checkInitializedWithoutEngine();
            mMinSdkVersion = minSdkVersion;
            return this;
        }

        /**
         * Sets whether the APK should be signed using JAR signing (aka v1 signature scheme).
         *
         * <p>By default, whether APK is signed using JAR signing is determined by {@code
         * ApkSigner}, based on the platform versions supported by the APK or specified using {@link
         * #setMinSdkVersion(int)}. Disabling JAR signing will result in APK signatures which don't
         * verify on Android Marshmallow (Android 6.0, API Level 23) and lower.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         *
         * @param enabled {@code true} to require the APK to be signed using JAR signing, {@code
         *                false} to require the APK to not be signed using JAR signing.
         * @throws IllegalStateException if this builder was initialized with an {@link
         *                               ApkSignerEngine}
         * @see <a
         * href="https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File">JAR
         * signing</a>
         */
        public Builder setV1SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            mV1SigningEnabled = enabled;
            return this;
        }

        /**
         * Sets whether the APK should be signed using APK Signature Scheme v2 (aka v2 signature
         * scheme).
         *
         * <p>By default, whether APK is signed using APK Signature Scheme v2 is determined by
         * {@code ApkSigner} based on the platform versions supported by the APK or specified using
         * {@link #setMinSdkVersion(int)}.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         *
         * @param enabled {@code true} to require the APK to be signed using APK Signature Scheme
         *                v2, {@code false} to require the APK to not be signed using APK Signature Scheme v2.
         * @throws IllegalStateException if this builder was initialized with an {@link
         *                               ApkSignerEngine}
         * @see <a href="https://source.android.com/security/apksigning/v2.html">APK Signature
         * Scheme v2</a>
         */
        public Builder setV2SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            mV2SigningEnabled = enabled;
            return this;
        }

        /**
         * Sets whether the APK should be signed using APK Signature Scheme v3 (aka v3 signature
         * scheme).
         *
         * <p>By default, whether APK is signed using APK Signature Scheme v3 is determined by
         * {@code ApkSigner} based on the platform versions supported by the APK or specified using
         * {@link #setMinSdkVersion(int)}.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         *
         * <p><em>Note:</em> APK Signature Scheme v3 only supports a single signing certificate, but
         * may take multiple signers mapping to different targeted platform versions.
         *
         * @param enabled {@code true} to require the APK to be signed using APK Signature Scheme
         *                v3, {@code false} to require the APK to not be signed using APK Signature Scheme v3.
         * @throws IllegalStateException if this builder was initialized with an {@link
         *                               ApkSignerEngine}
         */
        public Builder setV3SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            mV3SigningEnabled = enabled;
            if (enabled) {
                mV3SigningExplicitlyEnabled = true;
            } else {
                mV3SigningExplicitlyDisabled = true;
            }
            return this;
        }

        /**
         * Sets whether the APK should be signed using APK Signature Scheme v4.
         *
         * <p>V4 signing requires that the APK be v2 or v3 signed.
         *
         * @param enabled {@code true} to require the APK to be signed using APK Signature Scheme v2
         *                or v3 and generate an v4 signature file
         */
        public Builder setV4SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            mV4SigningEnabled = enabled;
            mV4ErrorReportingEnabled = enabled;
            return this;
        }

        /**
         * Sets whether errors during v4 signing should be reported and halt the signing process.
         *
         * <p>Error reporting for v4 signing is disabled by default, but will be enabled if the
         * caller invokes {@link #setV4SigningEnabled} with a value of true. This method is useful
         * for tools that enable v4 signing by default but don't want to fail the signing process if
         * the user did not explicitly request the v4 signing.
         *
         * @param enabled {@code false} to prevent errors encountered during the V4 signing from
         *                halting the signing process
         */
        public Builder setV4ErrorReportingEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            mV4ErrorReportingEnabled = enabled;
            return this;
        }

        /**
         * Sets whether to enable the verity signature algorithm for the v2 and v3 signature
         * schemes.
         *
         * @param enabled {@code true} to enable the verity signature algorithm for inclusion in the
         *                v2 and v3 signature blocks.
         */
        public Builder setVerityEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            mVerityEnabled = enabled;
            return this;
        }

        /**
         * Sets whether the APK should be signed even if it is marked as debuggable ({@code
         * android:debuggable="true"} in its {@code AndroidManifest.xml}). For backward
         * compatibility reasons, the default value of this setting is {@code true}.
         *
         * <p>It is dangerous to sign debuggable APKs with production/release keys because Android
         * platform loosens security checks for such APKs. For example, arbitrary unauthorized code
         * may be executed in the context of such an app by anybody with ADB shell access.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         */
        public Builder setDebuggableApkPermitted(boolean permitted) {
            checkInitializedWithoutEngine();
            mDebuggableApkPermitted = permitted;
            return this;
        }

        /**
         * Sets whether signatures produced by signers other than the ones configured in this engine
         * should be copied from the input APK to the output APK.
         *
         * <p>By default, signatures of other signers are omitted from the output APK.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         *
         * @throws IllegalStateException if this builder was initialized with an {@link
         *                               ApkSignerEngine}
         */
        public Builder setOtherSignersSignaturesPreserved(boolean preserved) {
            checkInitializedWithoutEngine();
            mOtherSignersSignaturesPreserved = preserved;
            return this;
        }

        /**
         * Sets the value of the {@code Created-By} field in JAR signature files.
         *
         * <p><em>Note:</em> This method may only be invoked when this builder is not initialized
         * with an {@link ApkSignerEngine}.
         *
         * @throws IllegalStateException if this builder was initialized with an {@link
         *                               ApkSignerEngine}
         */
        public Builder setCreatedBy(String createdBy) {
            checkInitializedWithoutEngine();
            if (createdBy == null) {
                throw new NullPointerException();
            }
            mCreatedBy = createdBy;
            return this;
        }

        private void checkInitializedWithoutEngine() {
            if (mSignerEngine != null) {
                throw new IllegalStateException(
                        "Operation is not available when builder initialized with an engine");
            }
        }

        /**
         * Sets the {@link SigningCertificateLineage} to use with the v3 signature scheme. This
         * structure provides proof of signing certificate rotation linking {@link SignerConfig}
         * objects to previous ones.
         */
        public Builder setSigningCertificateLineage(
                SigningCertificateLineage signingCertificateLineage) {
            if (signingCertificateLineage != null) {
                mV3SigningEnabled = true;
                mSigningCertificateLineage = signingCertificateLineage;
            }
            return this;
        }

        /**
         * Returns a new {@code ApkSigner} instance initialized according to the configuration of
         * this builder.
         */
        public ApkSigner build() {
            if (mV3SigningExplicitlyDisabled && mV3SigningExplicitlyEnabled) {
                throw new IllegalStateException(
                        "Builder configured to both enable and disable APK "
                                + "Signature Scheme v3 signing");
            }

            if (mV3SigningExplicitlyDisabled) {
                mV3SigningEnabled = false;
            }

            if (mV3SigningExplicitlyEnabled) {
                mV3SigningEnabled = true;
            }

            // If V4 signing is not explicitly set, and V2/V3 signing is disabled, then V4 signing
            // must be disabled as well as it is dependent on V2/V3.
            if (mV4SigningEnabled && !mV2SigningEnabled && !mV3SigningEnabled) {
                if (!mV4ErrorReportingEnabled) {
                    mV4SigningEnabled = false;
                } else {
                    throw new IllegalStateException(
                            "APK Signature Scheme v4 signing requires at least "
                                    + "v2 or v3 signing to be enabled");
                }
            }

            // TODO - if v3 signing is enabled, check provided signers and history to see if valid

            return new ApkSigner(
                    mSignerConfigs,
                    mSourceStampSignerConfig,
                    mSourceStampSigningCertificateLineage,
                    mForceSourceStampOverwrite,
                    mMinSdkVersion,
                    mV1SigningEnabled,
                    mV2SigningEnabled,
                    mV3SigningEnabled,
                    mV4SigningEnabled,
                    mVerityEnabled,
                    mV4ErrorReportingEnabled,
                    mDebuggableApkPermitted,
                    mOtherSignersSignaturesPreserved,
                    mSignerConfigsDisable,
                    mCreatedBy,
                    mSignerEngine,
                    mInputApkFile,
                    mInputApkDataSource,
                    mOutputApkFile,
                    mOutputApkDataSink,
                    mOutputApkDataSource,
                    mOutputV4File,
                    mInputBinFile,
                    mOutputBinFile,
                    binaryFormatItems,
                    mSigningCertificateLineage);
        }
    }
}

class ManifestOutput implements Serializable {
    public V1SchemeSigner.OutputManifestFileSerilizable manifestFile;
}

class ManifestOutputHashMap implements Serializable {
    public int minSdkVersion;
    public boolean v2SigningEnabled;
    public boolean v3SigningEnabled;
    public HashMap<DigestAlgorithm, ManifestOutput> manifestOutputHashMap = new HashMap<>();
}

class BinaryFormat {
    public String identifier;
    public String content;

    public BinaryFormat() {
    }

    public BinaryFormat(String _identifier, String _content) {
        identifier = _identifier;
        content = _content;
    }

    public BinaryFormat(String _identifier, SerializableContentDigestsAndMinSdkVersion _content) throws IOException {
        identifier = _identifier;
        content = toBase64String(_content);
    }

    public BinaryFormat(String _identifier, SerializableApkSigningBlock _content) throws IOException {
        identifier = _identifier;
        content = toBase64String(_content);
    }

    public static String toBase64String(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    public static Object fromBase64String(String s) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }
}

class SerializableContentDigestsAndMinSdkVersion implements Serializable {
    public int minSdkVersion;
    public HashMap<Integer, byte[]> contentDigests = new HashMap<>();

    public SerializableContentDigestsAndMinSdkVersion() {
    }

    public SerializableContentDigestsAndMinSdkVersion(
            Pair<Map<ContentDigestAlgorithm, byte[]>, Integer> _contentDigestsAndMinSdkVersion) {
        Map<ContentDigestAlgorithm, byte[]> _contentDigests = _contentDigestsAndMinSdkVersion.getFirst();
        int _minSdkVersion = _contentDigestsAndMinSdkVersion.getSecond();
        minSdkVersion = _minSdkVersion;
        contentDigests.put(1, _contentDigests.get(ContentDigestAlgorithm.CHUNKED_SHA256));
        contentDigests.put(2, _contentDigests.get(ContentDigestAlgorithm.CHUNKED_SHA512));
        contentDigests.put(3, _contentDigests.get(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256));
    }

    public Pair<Map<ContentDigestAlgorithm, byte[]>, Integer> toContentDigestsAndMinSdkVersion() {
        Map<ContentDigestAlgorithm, byte[]> _contentDigests = new HashMap<>();
        int _minSdkVersion = minSdkVersion;
        _contentDigests.put(ContentDigestAlgorithm.CHUNKED_SHA256, contentDigests.get(1));
        _contentDigests.put(ContentDigestAlgorithm.CHUNKED_SHA512, contentDigests.get(2));
        _contentDigests.put(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, contentDigests.get(3));
        return Pair.of(_contentDigests, _minSdkVersion);
    }
}

class SerializableApkSigningBlock implements Serializable {
    public byte[] apkSigningBlock;

    public SerializableApkSigningBlock() {
    }

    public SerializableApkSigningBlock(byte[] _apkSigningBlock) {
        apkSigningBlock = _apkSigningBlock;
    }

    public byte[] toApkSigningBlock() {
        return apkSigningBlock;
    }
}
