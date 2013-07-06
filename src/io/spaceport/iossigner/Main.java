package io.spaceport.iossigner;

import io.spaceport.iossigner.darwin.AppBundle;
import io.spaceport.iossigner.signing.AppleKeychain;
import io.spaceport.iossigner.signing.MobileProvision;
import io.spaceport.iossigner.signing.Pkcs12SigningIdentity;
import io.spaceport.iossigner.signing.SigningIdentity;
import io.spaceport.iossigner.signing.SigningIdentityProvider;
import io.spaceport.iossigner.ui.Command;
import io.spaceport.iossigner.ui.HelpPrinter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import sun.security.tools.JarSigner;
import sun.security.tools.KeyTool;

public class Main {
	protected static void printHelp(Map<String, Command> commandMap) {
		System.out.println("usage: sp-signer <command> [<args>]");
		System.out.println();
		
		System.out.println("Availale commands are:");
		HelpPrinter helpPrinter = new HelpPrinter(3, 11);
		for(Map.Entry<String, Command> entry : commandMap.entrySet()) {
			Command cmd = entry.getValue();
			
			// Don't include help
			if(cmd.getCommandString().equals("help"))
				continue;
			
			helpPrinter.addEntry(new HelpPrinter.Entry(cmd.getCommandString(), cmd.getQuickInfo()));
		}
		
		helpPrinter.print();
		System.out.println();
		System.out.println("See 'sp-signer help <command>' for more information on a specific command.");
		
		System.exit(1);
	}
	
	public static void main(String[] args) {
		final Map<String, Command> commandMap = new TreeMap<String, Command>();
		
		// Install a bouncycastle provider
		Security.addProvider(new BouncyCastleProvider());
		
		// sp-signer verify
		commandMap.put("verify", new Command("verify", "Verify signing information") {
			protected SigningIdentity signingIdentity = null;
			protected MobileProvision mobileProvision = null;
			protected ArrayList<String> uuids = new ArrayList<String>();
			
			@Override
			public int execute(String[] args) {
				int originalArgument = 0;
				int offendingArgument = 0;
				
				try {
					for(int i=0; i<args.length; ++i) {
						// ArrayIndexOutOfBoundsException does not have an offending index method, use this instead.
						originalArgument = i;
						offendingArgument = i;
						
						if("--mprovision".equals(args[i])) {
							assignMobileProvision(new MobileProvision(new FileInputStream(args[offendingArgument = ++i])));
						} else if("--apple-keychain".equals(args[i])) {
							assignSigningIdentity(new AppleKeychain().findIdentity(args[offendingArgument = ++i]));
						} else if("--pkcs12".equals(args[i])) {
							assignSigningIdentity(new Pkcs12SigningIdentity(new FileInputStream(args[offendingArgument = ++i]), null));
						} else if("--pkcs12-pw".equals(args[i])) {
							assignSigningIdentity(new Pkcs12SigningIdentity(new FileInputStream(args[offendingArgument = ++i]), args[offendingArgument = ++i]));
						} else if("--pkcs12-pwenv".equals(args[i])) {
							String fileName = args[offendingArgument  = ++i];
							String envVariable = args[offendingArgument = ++i];
							String password = System.getenv(envVariable);
							if(password == null) {
								System.err.println("Environment variable " + envVariable + " not set");
								return 1;
							}
							
							assignSigningIdentity(new Pkcs12SigningIdentity(new FileInputStream(fileName), password));
						} else if("--uuid".equals(args[i])) {
							uuids.add(args[offendingArgument = ++i]);
						} else {
							System.out.println("unknown argument: " + args[i]);
							showUsage();
						}
					}
					
					if(signingIdentity == null)
						error("Missing signing identity for verification");
					if(mobileProvision == null)
						error("Missing mobile provision for verification");
					
					if(!signingIdentity.isValid())
						error("Identity contains invalid certificates");
					if(!mobileProvision.isValid())
						error("Mobile provisioning is invalid or expired");
					if(!mobileProvision.containsIdentity(signingIdentity))
						error("Given identity is not a part of the mobile provisioning profile");
					if(!mobileProvision.getProvisionedDevices().containsAll(uuids))
						error("One of the given uuids are not present in the mobile provisioning profile");
					
					return 0;
				} catch(IllegalArgumentException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				} catch(FileNotFoundException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				} catch(ArrayIndexOutOfBoundsException e) {
					System.out.println("Missing argument for parameter " + args[originalArgument]);
					showUsage();
				} catch(IllegalStateException e) {
					System.err.println(e.getMessage());
					return 1;
				} catch (CertificateException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				} catch (IOException e) {
					System.err.println(args[offendingArgument] + ": " + e.getMessage());
					return 1;
				}
				
				return 0;
			}

			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer verify [<args>]");
				System.out.println();
				System.out.println("Availale arguments are:");
				new HelpPrinter(3, 11)
					.addEntry(new HelpPrinter.Entry("--apple-keychain <name>", "Use identity from apple keychain"))
					.addEntry(new HelpPrinter.Entry("--pkcs12 <file>", "Use identity from a non-encrypted PKCS12 file."))
					.addEntry(new HelpPrinter.Entry("--pkcs12-pw <file> <password>", "List identities from an encrypted PKCS12 file using a password."))
					.addEntry(new HelpPrinter.Entry("--pkcs12-pwenv <file> <env>", "Use identity from an encrypted PKCS12 file using a password stored in an environment variable."))
					.addEntry(new HelpPrinter.Entry("--mprovision <file>", "Mobile provisioning containing given identity and mobile uuid"))
					.addEntry(new HelpPrinter.Entry("--uuid <file>", "Validate presense of device uuid"))
					.print();

				super.showUsage();
			}
			
			protected void error(String errorString) {
				System.err.println(errorString);
				System.exit(1);
			}
			
			protected void assignSigningIdentity(SigningIdentity identity) {
				if(signingIdentity != null)
					error("Cannot specify more than one identity");
				
				signingIdentity = identity;
			}
			
			protected void assignMobileProvision(MobileProvision mp) {
				if(mobileProvision != null)
					error("Cannot specify more than one identity");
				
				mobileProvision = mp;
			}
		});
		
		commandMap.put("keytool",  new Command("keytool", "[jdk] Key and Certificate Management Tool") {
			@Override
			public int execute(String[] args) {
				try {
					KeyTool.main(args);
					return 0;
				} catch(Exception e) {
					System.err.println(e.getMessage());
					return 1;
				}
			}
		});
		
		commandMap.put("jarsigner", new Command("jarsigner", "[jdk] Jar signing utility") {
			@Override
			public int execute(String[] args) {
				try {
					JarSigner.main(args);
					return 0;
				} catch(Exception e) {
					System.err.println(e.getMessage());
					return 1;
				}
			}
		});
		
		// sp-signer info
		commandMap.put("info", new Command("info", "List information about a mobile provisioning profile") {
			@Override
			public int execute(String[] args) {
				if(args.length < 1)
					showUsage();
				
				boolean showJson = false;
				String fileName = args[args.length - 1];

				for(int i=0; i<args.length-1; ++i) {
					if("--json".equals(args[i]))
						showJson = true;
					else {
						System.out.println("unknown argument: " + args[i]);
						showUsage();
					}
				}
				
				try {
					MobileProvision prov = new MobileProvision(new FileInputStream(fileName));
					if(showJson) {
						try {
							JSONObject result = new JSONObject();
							result.put("name", prov.getName());
							result.put("valid", prov.isValid());
							result.put("release", prov.isRelease());
							result.put("expiry", prov.validBefore().getTime());
							result.put("application-identifier", prov.getApplicationIdentifier());
							result.put("provisionedDevices", new JSONArray(prov.getProvisionedDevices()));
							System.out.println(result.toString(0));
						} catch (JSONException e) {
							// Assume failure?
							System.err.println("Failed to generate json: " + e.getMessage());
							return 1;
						}
					} else {
						System.out.println("Provisioning profile " + fileName + ":");
						System.out.println("\tName: " + prov.getName());
						System.out.println("\tValid: " + prov.isValid());
						System.out.println("\tConfiguration: " + (prov.isRelease() ? "Release" : "Debug"));
						System.out.println("\tProvisioned Devices:");
						System.out.println("\tExpiry Date: " + prov.validBefore());
						for(Iterator<String> uuids=prov.getProvisionedDevices().iterator(); uuids.hasNext();)
							System.out.println("\t\t" + uuids.next());
					}
					
					// Return code is validation as well
					return 0;
				} catch(IllegalArgumentException e) {
					System.err.println(e.getMessage() + ": " + args[0]);
					return 1;
				} catch(FileNotFoundException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				}
			}
			
			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer info [<args>] <mobileprovision>");
				System.out.println();
				
				System.out.println("Availale arguments are:");
				HelpPrinter helpPrinter = new HelpPrinter(3, 11);
				helpPrinter.addEntry(new HelpPrinter.Entry("--json", "Output in a parsable json format"));
				helpPrinter.print();
				
				super.showUsage();
			}
		});
		
		// io-signer list
		commandMap.put("list", new Command("list", "List available signing identities") {
			@Override
			public int execute(String[] args) {
				MobileProvision provision = null;
				List<SigningIdentityProvider> identityProviders = new ArrayList<SigningIdentityProvider>();
				
				try {
					for(int i=0; i<args.length; ++i) {
						if(args[i].equals("--mprovision")) {
							// Only one mobile provision can be given at a time
							if(provision != null) {
								System.err.println("Only one mobile provisioning profile can be given");
								return 1;
							}
							
							provision = new MobileProvision(new FileInputStream(args[++i]));
						} else if(args[i].equals("--apple-keychain")) {
							identityProviders.add(new AppleKeychain());
						} else if(args[i].equals("--pkcs12")) {
							identityProviders.add(new Pkcs12SigningIdentity(new FileInputStream(args[++i]), null));
						} else if(args[i].equals("--pkcs12-pw")) {
							identityProviders.add(new Pkcs12SigningIdentity(new FileInputStream(args[++i]), args[++i]));
						} else if("--pkcs12-pwenv".equals(args[i])) {
							String fileName = args[++i];
							String envVariable = args[++i];
							String password = System.getenv(envVariable);
							if(password == null) {
								System.err.println("Environment variable " + envVariable + " not set");
								return 1;
							}
							
							identityProviders.add(new Pkcs12SigningIdentity(new FileInputStream(fileName), password));
						} else {
							System.err.println("Unknown argument " + args[i]);
							showUsage();
						}
					}
				} catch(FileNotFoundException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				} catch(IOException e) {
					System.err.println("Identity cannot be authenticated: " + e.getMessage());
					return 1;
				} catch(CertificateException e) {
					System.err.println("Identity cannot be authenticated: " + e.getMessage());
					return 1;
				}
				
				if(identityProviders.isEmpty())
					showUsage();
				
				for(SigningIdentityProvider sip : identityProviders) {
					for(Iterator<? extends SigningIdentity> identity=sip.identities(); identity.hasNext();) {
						SigningIdentity signingIdentity = identity.next();
						
						// If a provisioning profile was included, do not show unless the developer is a part of it
						if(provision != null && !provision.containsIdentity(signingIdentity))
							continue;
						
						if(signingIdentity.isValid())
							System.out.println(signingIdentity.getName());
					}
					
					System.out.println();
				}

				return 0;
			}
			
			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer list [<args>]");
				System.out.println();
				System.out.println("Availale arguments are:");
				new HelpPrinter(3, 11)
					.addEntry(new HelpPrinter.Entry("--apple-keychain", "List identities from Apple keychain."))
					.addEntry(new HelpPrinter.Entry("--pkcs12 <file>", "List identities from a non-encrypted PKCS12 file."))
					.addEntry(new HelpPrinter.Entry("--pkcs12-pw <file> <password>", "List identities from an encrypted PKCS12 file using a password."))
					.addEntry(new HelpPrinter.Entry("--pkcs12-pwenv <file> <env>", "List identities from an encrypted PKCS12 file using a password stored in an environment variable."))
					.addEntry(new HelpPrinter.Entry("--mprovision <file>", "Use a mobile provision to filter identities."))
					.print();
				
				super.showUsage();
			}
		});
		
		// sp-signer sign
		commandMap.put("sign-bundle", new Command("sign-bundle", "Sign an app bundle using a signing identity") {
			protected SigningIdentity signingIdentity = null;
			protected MobileProvision mobileProvision = null;
			
			@Override
			public int execute(String[] args) {
				int originalArgument = 0;
				int offendingArgument = 0;
				
				if(args.length < 1)
					showUsage();
				
				try {
					AppBundle bundle = new AppBundle();
					bundle.open(args[0]);
					
					for(int i=1; i<args.length; ++i) {
						// ArrayIndexOutOfBoundsException does not have an offending index method, use this instead.
						originalArgument = i;
						offendingArgument = i;
						
						if("--mprovision".equals(args[i])) {
							assignMobileProvision(new MobileProvision(new FileInputStream(args[offendingArgument = ++i])));
						} else if("--apple-keychain".equals(args[i])) {
							assignSigningIdentity(new AppleKeychain().findIdentity(args[offendingArgument = ++i]));
						} else if("--pkcs12".equals(args[i])) {
							assignSigningIdentity(new Pkcs12SigningIdentity(new FileInputStream(args[offendingArgument = ++i]), null));
						} else if("--pkcs12-pw".equals(args[i])) {
							assignSigningIdentity(new Pkcs12SigningIdentity(new FileInputStream(args[offendingArgument = ++i]), args[offendingArgument = ++i]));
						} else if("--pkcs12-pwenv".equals(args[i])) {
							String fileName = args[offendingArgument  = ++i];
							String envVariable = args[offendingArgument = ++i];
							String password = System.getenv(envVariable);
							if(password == null) {
								System.err.println("Environment variable " + envVariable + " not set");
								return 1;
							}
							
							assignSigningIdentity(new Pkcs12SigningIdentity(new FileInputStream(fileName), password));
						} else {
							System.out.println("unknown argument: " + args[i]);
							showUsage();
						}
					}
					
					if(signingIdentity == null)
						error("Missing signing identity for signing");
					if(mobileProvision == null)
						error("Missing mobile provision for signing");
					
					if(!signingIdentity.isValid())
						error("Identity contains invalid certificates");
					if(!mobileProvision.isValid())
						error("Mobile provisioning is invalid or expired");
					if(!mobileProvision.containsIdentity(signingIdentity))
						error("Given identity is not a part of the mobile provisioning profile");
					
					// Copy the provision profile to the bundle before signing
					mobileProvision.writeTo(new File(bundle.bundlePath() + "/embedded.mobileprovision"));
					
					// Sign the bundle
					Signer signer = new Signer(bundle);
					signer.sign(mobileProvision, signingIdentity);
					
					return 0;
				} catch(IllegalArgumentException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				} catch(FileNotFoundException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				} catch(ArrayIndexOutOfBoundsException e) {
					System.out.println("Missing argument for parameter " + args[originalArgument]);
					showUsage();
				} catch(IllegalStateException e) {
					System.err.println(e.getMessage());
					return 1;
				} catch (CertificateException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				} catch (IOException e) {
					System.err.println(args[offendingArgument] + ": " + e.getMessage());
					return 1;
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				return 0;
			}

			protected void error(String errorString) {
				System.out.println(errorString);
				System.out.println();
				showUsage();
			}
			
			protected void assignSigningIdentity(SigningIdentity identity) {
				if(signingIdentity != null)
					error("Cannot specify more than one identity");
				
				signingIdentity = identity;
			}
			
			protected void assignMobileProvision(MobileProvision mp) {
				if(mobileProvision != null)
					error("Cannot specify more than one identity");
				
				mobileProvision = mp;
			}
			
			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer sign-bundle <bundle.app> [<args>]");
				System.out.println();
				System.out.println("Availale arguments are:");
				new HelpPrinter(3, 11)
					.addEntry(new HelpPrinter.Entry("--apple-keychain <name>", "Use identity from apple keychain"))
					.addEntry(new HelpPrinter.Entry("--pkcs12 <file>", "Use identity from a non-encrypted PKCS12 file."))
					.addEntry(new HelpPrinter.Entry("--pkcs12-pw <file> <password>", "List identities from an encrypted PKCS12 file using a password."))
					.addEntry(new HelpPrinter.Entry("--pkcs12-pwenv <file> <env>", "Use identity from an encrypted PKCS12 file using a password stored in an environment variable."))
					.addEntry(new HelpPrinter.Entry("--mprovision <file>", "Mobile provisioning containing given identity and mobile uuid"))
					.print();

				super.showUsage();
			}
		});

		commandMap.put("keygen", new Command("keygen", "Generate an RSA keypair") {
			@Override
			public int execute(String[] args) {
				int originalArgument = 0;
				int offendingArgument = 0;
				
				try {
					int strength = 0;
					String outputFilename = args[0];
					
					for(int i=1; i<args.length; ++i) {
						// ArrayIndexOutOfBoundsException does not have an offending index method, use this instead.
						originalArgument = i;
						offendingArgument = i;
						
						if("--strength".equals(args[i])) {
							if(strength != 0)
								throw new IllegalArgumentException("Argument specified more than once");
							
							strength = Integer.parseInt(args[offendingArgument = ++i], 10);
						} else {
							System.out.println("unknown argument: " + args[i]);
							showUsage();
						}
					}
					
					KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
					keygen.initialize(strength);
					
					PEMWriter writer = null;
					try {
						writer = new PEMWriter(new FileWriter(outputFilename));
						writer.writeObject(keygen.generateKeyPair());
					} finally {
						if(writer != null)
							writer.close();
					}
				} catch(IOException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				} catch(NoSuchProviderException e) {
					System.err.println("Fatal error: " + e.getMessage());
					return 1;
				} catch(NoSuchAlgorithmException e) {
					System.err.println("Fatal error: " + e.getMessage());
					return 1;
				} catch(ArrayIndexOutOfBoundsException e) {
					System.out.println("Missing argument for parameter " + args[originalArgument]);
					showUsage();
				} catch(IllegalArgumentException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				}

				return 0;
			}
			
			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer keygen <output> [<args>]");
				System.out.println();
				System.out.println("Availale arguments are:");
				new HelpPrinter(3, 11)
					.addEntry(new HelpPrinter.Entry("--strength <int>", "Strength of the key in bits (default = 2048)"))
					.print();

				super.showUsage();
			}
		});
		
		commandMap.put("csr", new Command("csr", "Create a certificate signing request for a key") {
			@Override
			public int execute(String[] args) {
				int originalArgument = 0;
				int offendingArgument = 0;
				
				try {
					String outputFilename = args[0];
					String privateKeyFilename = args[1];
					List<String> attributes = new ArrayList<String>();
					
					for(int i=2; i<args.length; ++i) {
						// ArrayIndexOutOfBoundsException does not have an offending index method, use this instead.
						originalArgument = i;
						offendingArgument = i;
						
						if("--email".equals(args[i])) {
							attributes.add("emailAddress=\"" + args[offendingArgument = ++i] + "\"");
						} else if("--common-name".equals(args[i])) {
							attributes.add("CN=\"" + args[offendingArgument = ++i] + "\"");
						} else if("--country".equals(args[i])) {
							attributes.add("C=\"" + args[offendingArgument = ++i] + "\"");
						} else if("--organization".equals(args[i])) {
							attributes.add("O=\"" + args[offendingArgument = ++i] + "\"");
						} else if("--organization-unit".equals(args[i])) {
							attributes.add("OU=\"" + args[offendingArgument = ++i] + "\"");
						} else {
							System.out.println("unknown argument: " + args[i]);
							showUsage();
						}
					}
					
					// Generate principal string
					String principalString = "";
					{
					    Iterator<String> attribute = attributes.iterator();
						while(attribute.hasNext()) {
							principalString += attribute.next();
							if(attribute.hasNext())
								principalString += ", ";
						}
					}
					
					// Read private keypair
					KeyPair keyPair = null;
					{
						FileReader privateKeyReader = null;
						PEMReader reader = null;
						
						try {
							privateKeyReader = new FileReader(privateKeyFilename);
							reader = new PEMReader(privateKeyReader);
							
							keyPair = (KeyPair)reader.readObject();
						} finally {
							if(reader != null)
								reader.close();
							if(privateKeyReader != null)
								privateKeyReader.close();
						}
					}
					
					if(keyPair == null)
						throw new IllegalArgumentException("Error obtaining private key");
					
					@SuppressWarnings("deprecation") // The new, undeprecated version does not write to PEM files.
					PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WITHRSAENCRYPTION", new X500Principal(principalString), keyPair.getPublic(), new DERSet(), keyPair.getPrivate());
					{
						FileWriter csrWriter = null;
						PEMWriter writer = null;
						try {
							csrWriter = new FileWriter(outputFilename);
							
							writer = new PEMWriter(csrWriter);
							writer.writeObject(req);
						} finally {
							if(writer != null)
								writer.close();
							if(csrWriter != null)
								csrWriter.close();
						}
					}
				} catch(IOException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				} catch(NoSuchProviderException e) {
					System.err.println("Fatal error: " + e.getMessage());
					return 1;
				} catch(NoSuchAlgorithmException e) {
					System.err.println("Fatal error: " + e.getMessage());
					return 1;
				} catch(ArrayIndexOutOfBoundsException e) {
					System.out.println("Missing argument for parameter " + args[originalArgument]);
					showUsage();
				} catch(IllegalArgumentException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				} catch (InvalidKeyException e) {
					System.err.println("Failed to generate certificate request: " + e.getMessage());
					return 1;
				} catch (SignatureException e) {
					System.err.println("Failed to generate certificate request: " + e.getMessage());
					return 1;
				}

				return 0;
			}
			
			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer csr <output> <privateKey> [<args>]");
				System.out.println();
				System.out.println("Availale arguments are:");
				new HelpPrinter(3, 11)
					.addEntry(new HelpPrinter.Entry("--email <address>", "Add an email alias"))
					.addEntry(new HelpPrinter.Entry("--common-name <name>", "Add a common name alias"))
					.addEntry(new HelpPrinter.Entry("--country <code>", "Add an ISO country code"))
					.addEntry(new HelpPrinter.Entry("--organization <code>", "Add an organization name"))
					.addEntry(new HelpPrinter.Entry("--organization-unit <code>", "Add an organization unit (subdivision) name"))
					.print();
			
				super.showUsage();
			}
		});
		
		commandMap.put("pkcs12", new Command("pkcs12", "Package an X509 certificate and a private key into a PKCS12 Identity file") {
			protected String getCommonName(X509Certificate certificate) {
				try {
					X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
					RDN cn = x500name.getRDNs(BCStyle.CN)[0];
	
					return IETFUtils.valueToString(cn.getFirst().getValue());
				} catch(CertificateEncodingException e) {
					return null;
				}
			}
			
			@Override
			public int execute(String[] args) {
				if(args.length < 1)
					showUsage();
				
				int originalArgument = 0;
				int offendingArgument = 0;
				
				try {
					CertificateFactory x509Factory = CertificateFactory.getInstance("X.509", "BC");
					
					String keyFilename = null;
					String certFilename = null;
					String outputFilename = args[0];
					String encryptionPassword = "";
					
					for(int i=1; i<args.length; ++i) {
						// ArrayIndexOutOfBoundsException does not have an offending index method, use this instead.
						originalArgument = i;
						offendingArgument = i;
						
						if("--x509-certificate".equals(args[i])) {
							if(certFilename != null)
								throw new IllegalArgumentException("Cannot specify more than one certificate");
							
							certFilename = args[offendingArgument = ++i];
						} else if("--key".equals(args[i])) {
							if(keyFilename != null)
								throw new IllegalArgumentException("Cannot specify more than one private key");
							
							keyFilename = args[offendingArgument = ++i];
						} else if("--password".equals(args[i])) { 
							encryptionPassword = args[offendingArgument = ++i];
						} else {
							System.out.println("unknown argument: " + args[i]);
							showUsage();
						}
					}
					
					// Read certificate
					X509Certificate iosDeveloperCertificate = null;
					if(certFilename != null) {
						FileInputStream certFileStream = null;
						try {
							certFileStream = new FileInputStream(certFilename);
							iosDeveloperCertificate = (X509Certificate)x509Factory.generateCertificate(certFileStream);
						} finally {
							if(certFileStream != null)
								certFileStream.close();
						}
					} else {
						offendingArgument = 0;
						throw new IllegalArgumentException("Missing X509 Certificate for PKCS12 bundle");
					}
					
					// Read private keypair
					KeyPair keyPair = null;
					if(keyFilename != null) {
						FileReader privateKeyReader = null;
						PEMReader reader = null;
						
						try {
							privateKeyReader = new FileReader(keyFilename);
							reader = new PEMReader(privateKeyReader);
							
							keyPair = (KeyPair)reader.readObject();
						} finally {
							if(reader != null)
								reader.close();
							if(privateKeyReader != null)
								privateKeyReader.close();
						}
					}
					
					String alias = getCommonName(iosDeveloperCertificate);
					
					KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
					keyStore.load(null, null);
					
					// Publicly facing certificate
					if(iosDeveloperCertificate != null)
						keyStore.setCertificateEntry(alias,  iosDeveloperCertificate);
					
					// Private signing key
					if(keyPair != null)
						keyStore.setKeyEntry(alias, keyPair.getPrivate(), "".toCharArray(), new Certificate[] { iosDeveloperCertificate });
					
					// Export
					FileOutputStream output = null;
					try {
						output = new FileOutputStream(outputFilename);
						keyStore.store(output, encryptionPassword.toCharArray());
					} finally {
						if(output != null)
							output.close();
					}
				} catch(IOException e) {
					System.err.println("Failed to open " + e.getMessage());
					return 1;
				} catch(NoSuchProviderException e) {
					System.err.println("Fatal error: " + e.getMessage());
					return 1;
				} catch(NoSuchAlgorithmException e) {
					System.err.println("Fatal error: " + e.getMessage());
					return 1;
				} catch(ArrayIndexOutOfBoundsException e) {
					System.out.println("Missing argument for parameter " + args[originalArgument]);
					showUsage();
				} catch(IllegalArgumentException e) {
					System.err.println(e.getMessage() + ": " + args[offendingArgument]);
					return 1;
				} catch (CertificateException e) {
					System.err.println("Failed to encrypt PKCS12: " + e.getMessage());
					return 1;
				} catch (KeyStoreException e) {
					System.err.println("Failed to package PKCS12: " + e.getMessage());
					return 1;
				}

				return 0;
			}
			
			@Override
			public void showUsage() {
				System.out.println("usage: sp-signer pkcs12 <output> [<args>]");
				System.out.println();
				System.out.println("Availale arguments are:");
				new HelpPrinter(3, 11)
					.addEntry(new HelpPrinter.Entry("--key <filename>", "Package a private key"))
					.addEntry(new HelpPrinter.Entry("--x509-certificate <name>", "Package an x509 certificate"))
					.addEntry(new HelpPrinter.Entry("--password <string>", "Encrypt PKCS12 store with this password"))
					.print();
			
				super.showUsage();
			}
		});
		
		// Add help after we printed help
		commandMap.put("help", new Command("help", "Show more information about a perticular command") {
			@Override
			public int execute(String[] args) {
				if(args.length != 1 || !commandMap.containsKey(args[0])) {
					showUsage();
					return 1;
				}
				
				commandMap.get(args[0]).showUsage();
				return 0;
			}
			
			@Override
			public void showUsage() {
				printHelp(commandMap);
			}
		});
		
		// Show global usage
		if(args.length < 1 || !commandMap.containsKey(args[0]))
			printHelp(commandMap);
		
		// Execute command
		System.exit(commandMap.get(args[0]).execute(Arrays.copyOfRange(args, 1, args.length)));
	}
}
