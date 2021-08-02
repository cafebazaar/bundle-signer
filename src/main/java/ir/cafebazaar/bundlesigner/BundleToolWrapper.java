package ir.cafebazaar.bundlesigner;

import com.android.tools.build.bundletool.commands.BuildApksCommand;
import com.android.tools.build.bundletool.device.AdbServer;
import com.android.tools.build.bundletool.device.DdmlibAdbServer;
import com.android.tools.build.bundletool.flags.FlagParser;
import com.android.tools.build.bundletool.flags.ParsedFlags;
import ir.cafebazaar.apksig.ApkSigner;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.util.ArrayList;

public class BundleToolWrapper {

    private static File keyStore;
    private static final Logger logger = Logger.getLogger(String.valueOf(BundleToolWrapper.class));


    static {
        try {
            keyStore = loadDefaultKeyStore();
            logger.info("loaded keystore.");
        } catch (IOException e) {
            e.printStackTrace();
            logger.info(e.getStackTrace());
        }
    }


    public static File loadDefaultKeyStore() throws IOException {
        String keyStoreName = "default.keystore";
        InputStream inputStream = ApkSigner.class.getClassLoader().getResourceAsStream(keyStoreName);
        File keyStore = new File(BundleSignerTool.TMP_DIR_PATH + File.separator + keyStoreName);
        Files.copy(inputStream, keyStore.toPath());
        return keyStore;
    }

    public static String buildApkSet(File bundle, String outputPath, boolean universalMode)
            throws BundleToolIOException {

        String bundleName;
        if (universalMode) {
            bundleName = "universal";
        } else {
            bundleName = bundle.getName().split("\\.")[0];
        }
        String apksPath = outputPath + File.separator + bundleName + ".apks";

        ArrayList<String> args = new ArrayList<>();
        args.add("--bundle");
        args.add(bundle.getAbsolutePath());
        args.add("--output");
        args.add(apksPath);
        args.add("--ks");
        args.add(keyStore.getAbsolutePath());
        args.add("--ks-key-alias=default");
        args.add("--ks-pass=pass:defaultpass");
        if (universalMode) {
            args.add("--mode=universal");
        }

        try (AdbServer adbServer = DdmlibAdbServer.getInstance()) {
            final ParsedFlags flags;
            flags = new FlagParser().parse(args.toArray(new String[args.size()]));
            BuildApksCommand.fromFlags(flags, adbServer).execute();
        } catch (UncheckedIOException e) {
            throw new BundleToolIOException(e.getMessage());
        }
        logger.info(String.format("Built apkset. Mode is %s", universalMode));
        return apksPath;
    }

}
