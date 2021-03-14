# bundle signer
App Bundle is a publishing format for Android applications which includes all your app compiled code and resources.
Bazaar uses your app bundle to generate and publish optimized packages for devices with different configurations.
With this new feature, you don’t need to build and manage APKs to have optimized applications for different devices,
and users will receive smaller and more optimized apps.
we do not get and save your application signing key to keep your app security. Instead, we presented you with a 
bundle signer tool, which you can use to sign your app offline, on your device. You just give us your signed binary 
file for generating application packages.

# Usage 

```sh
$ java -jar bundlesigner-0.1.0.jar genbin  -v --bundle app.aab --bin /home/bin_files/
       --v2-signing-enabled true --v3-signing-enabled false
       --key dsa-1024.pk8  --cert dsa-1024.x509.pem
```
This generates signed digest of the provided bundle. The output of this command
is a binary file that contains signed digest of all APK files that can be
extracted from the bundle. Signing is performed using one or more signers,
each represented by an asymmetric key pair and a corresponding certificate.
Typically, signing is done using just one signer. For each signer,
you need to provide the signer's private key and certificate.

         GENERAL OPTIONS

--bundle              Input Bundle file to generate its signed content.

--bin                 Output path of desired directory to save the generated bin file.

-v, --verbose         Verbose output mode

--v2-signing-enabled  Whether to enable signing using APK Signature Scheme v2
(aka v2 signing scheme) introduced in Android Nougat,
API Level 24.

--v3-signing-enabled  Whether to enable signing using APK Signature Scheme v3
(aka v3 signing scheme) introduced in Android P,
API Level 28.

--force-stamp-overwrite  Whether to overwrite existing source stamp in the
APK, if found. By default, it is set to false. It has no
effect if no source stamp signer config is provided.

--verity-enabled      Whether to enable the verity signature algorithm for the
v2 and v3 signature schemes.

--min-sdk-version     Lowest API Level on which this bundle's signatures will be
verified. By default, the value from AndroidManifest.xml
is used. The higher the value, the stronger security
parameters are used when signing.

--max-sdk-version     Highest API Level on which this bundle's signatures will be
verified. By default, the highest possible value is used.

-h, --help            Show help about this command and exit


         PER-SIGNER OPTIONS
These options specify the configuration of a particular signer. To delimit
options of different signers, use --next-signer.

--next-signer         Delimits options of two different signers. There is no
need to use this option when only one signer is used.

--stamp-signer        The signing information for the signer of the source stamp
to be included in the APK.

         PER-SIGNER SIGNING KEY & CERTIFICATE OPTIONS
There are two ways to provide the signer's private key and certificate: (1) Java
KeyStore (see --ks), or (2) private key file in PKCS #8 format and certificate
file in X.509 format (see --key and --cert).

--ks                  Load private key and certificate chain from the Java
KeyStore initialized from the specified file. NONE means
no file is needed by KeyStore, which is the case for some
PKCS #11 KeyStores.

--ks-key-alias        Alias under which the private key and certificate are
stored in the KeyStore. This must be specified if the
KeyStore contains multiple keys.

--ks-pass             KeyStore password (see --ks). The following formats are
supported:
pass:<password> password provided inline
env:<name>      password provided in the named
environment variable
file:<file>     password provided in the named
file, as a single line
stdin           password provided on standard input,
as a single line
A password is required to open a KeyStore.
By default, the tool will prompt for password via console
or standard input.
When the same file (including standard input) is used for
providing multiple passwords, the passwords are read from
the file one line at a time. Passwords are read in the
order in which signers are specified and, within each
signer, KeyStore password is read before the key password
is read.

--key-pass            Password with which the private key is protected.
The following formats are supported:
pass:<password> password provided inline
env:<name>      password provided in the named
environment variable
file:<file>     password provided in the named
file, as a single line
stdin           password provided on standard input,
as a single line
If --key-pass is not specified for a KeyStore key, this
tool will attempt to load the key using the KeyStore
password and, if that fails, will prompt for key password
and attempt to load the key using that password.
If --key-pass is not specified for a private key file key,
this tool will prompt for key password only if a password
is required.
When the same file (including standard input) is used for
providing multiple passwords, the passwords are read from
the file one line at a time. Passwords are read in the
order in which signers are specified and, within each
signer, KeyStore password is read before the key password
is read.

--pass-encoding       Additional character encoding (e.g., ibm437 or utf-8) to
try for passwords containing non-ASCII characters.
KeyStores created by keytool are often encrypted not using
the Unicode form of the password but rather using the form
produced by encoding the password using the console's
character encoding. bundlesigner by default tries to decrypt
using several forms of the password: the Unicode form, the
form encoded using the JVM default charset, and, on Java 8
and older, the form encoded using the console's charset.
On Java 9, bundlesigner cannot detect the console's charset
and may need to be provided with --pass-encoding when a
non-ASCII password is used. --pass-encoding may also need
to be provided for a KeyStore created by keytool on a
different OS or in a different locale.

--ks-type             Type/algorithm of KeyStore to use. By default, the default
type is used.

--ks-provider-name    Name of the JCA Provider from which to request the
KeyStore implementation. By default, the highest priority
provider is used. See --ks-provider-class for the
alternative way to specify a provider.

--ks-provider-class   Fully-qualified class name of the JCA Provider from which
to request the KeyStore implementation. By default, the
provider is chosen based on --ks-provider-name.

--ks-provider-arg     Value to pass into the constructor of the JCA Provider
class specified by --ks-provider-class. The value is
passed into the constructor as java.lang.String. By
default, the no-arg provider's constructor is used.

--key                 Load private key from the specified file. If the key is
password-protected, the password will be prompted via
standard input unless specified otherwise using
--key-pass. The file must be in PKCS #8 DER format.

--cert                Load certificate chain from the specified file. The file
must be in X.509 PEM or DER format.


         JCA PROVIDER INSTALLATION OPTIONS
These options enable you to install additional Java Crypto Architecture (JCA)
Providers, such as PKCS #11 providers. Use --next-provider to delimit options of
different providers. Providers are installed in the order in which they appear
on the command-line.

--provider-class      Fully-qualified class name of the JCA Provider.

--provider-arg        Value to pass into the constructor of the JCA Provider
class specified by --provider-class. The value is passed
into the constructor as java.lang.String. By default, the
no-arg provider's constructor is used.

--provider-pos        Position / priority at which to install this provider in
the JCA provider list. By default, the provider is
installed as the lowest priority provider.
See java.security.Security.insertProviderAt.

