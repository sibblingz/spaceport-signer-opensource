// For some reason, we get an exception when this is placed
// in io.spaceport.iossigner.darwin:
//
// org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory$ExCertificateException
//     at org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory.engineGenerateCertificate(Unknown Source)
//     at java.security.cert.CertificateFactory.generateCertificate(CertificateFactory.java:305)
//     at io.spaceport.iossigner.darwin.BundleSigner.generatePkcs7Certificate(Unknown Source)
//     at io.spaceport.iossigner.darwin.BundleSigner.sign(Unknown Source)
//     at io.spaceport.iossigner.Main$6.execute(Unknown Source)
//     at io.spaceport.iossigner.Main.main(Unknown Source)
// Caused by: java.io.IOException: Stream closed
//     at java.io.PushbackInputStream.ensureOpen(PushbackInputStream.java:57)
//     at java.io.PushbackInputStream.read(PushbackInputStream.java:118)
//     ... 6 more
//
// So sorry, you can't move this file!

package io.spaceport.iossigner;

import io.spaceport.iossigner.blobs.CodeDirectoryBlob;
import io.spaceport.iossigner.blobs.DataBlob;
import io.spaceport.iossigner.blobs.SuperBlob;
import io.spaceport.iossigner.darwin.AppBundle;
import io.spaceport.iossigner.signing.MobileProvision;
import io.spaceport.iossigner.signing.SigningIdentity;
import io.spaceport.iossigner.utils.FileUtils;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.dd.plist.NSDictionary;
import com.dd.plist.PropertyListParser;

public class Signer {
	// Hardcoded requirement set for spaceport
	// XXX: This can change, so hopefully we'll reverse engineer this before shit hits the fan
	static final private byte[] SPACEPORT_REQUIREMENTS = new byte[] {
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x16, 0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70, 0x6C,
		0x65, 0x2E, 0x61, 0x76, 0x66, 0x6F, 0x75, 0x6E, 0x64, 0x61, 0x74, 0x69,
		0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x63, 0x6F, 0x6D, 0x2E,
		0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x51, 0x75, 0x61, 0x72, 0x74, 0x7A,
		0x43, 0x6F, 0x72, 0x65, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x63, 0x6F, 0x6D, 0x2E,
		0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x46, 0x6F, 0x75, 0x6E, 0x64, 0x61,
		0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24, 0x63, 0x6F, 0x6D, 0x2E,
		0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x61, 0x75, 0x64, 0x69, 0x6F, 0x2E,
		0x74, 0x6F, 0x6F, 0x6C, 0x62, 0x6F, 0x78, 0x2E, 0x41, 0x75, 0x64, 0x69,
		0x6F, 0x54, 0x6F, 0x6F, 0x6C, 0x62, 0x6F, 0x78, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x19,
		0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x61, 0x75,
		0x64, 0x69, 0x6F, 0x2E, 0x43, 0x6F, 0x72, 0x65, 0x41, 0x75, 0x64, 0x69,
		0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16, 0x63, 0x6F, 0x6D, 0x2E,
		0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x61, 0x75, 0x64, 0x69, 0x6F, 0x2E,
		0x4F, 0x70, 0x65, 0x6E, 0x41, 0x4C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1D,
		0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x53, 0x79,
		0x73, 0x74, 0x65, 0x6D, 0x43, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x75, 0x72,
		0x61, 0x74, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x12,
		0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x53, 0x74,
		0x6F, 0x72, 0x65, 0x4B, 0x69, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0B,
		0x6C, 0x69, 0x62, 0x73, 0x74, 0x64, 0x63, 0x2B, 0x2B, 0x2E, 0x36, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x0B, 0x6C, 0x69, 0x62, 0x53, 0x79, 0x73, 0x74, 0x65,
		0x6D, 0x2E, 0x42, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0B, 0x6C, 0x69, 0x62, 0x53,
		0x79, 0x73, 0x74, 0x65, 0x6D, 0x2E, 0x42, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x18,
		0x63, 0x6F, 0x6D, 0x2E, 0x61, 0x70, 0x70, 0x6C, 0x65, 0x2E, 0x43, 0x6F,
		0x72, 0x65, 0x46, 0x6F, 0x75, 0x6E, 0x64, 0x61, 0x74, 0x69, 0x6F, 0x6E,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x09, 0x6C, 0x69, 0x62, 0x6F, 0x62, 0x6A, 0x63, 0x2E,
		0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	};
	
	private MessageDigest sha1;
	protected AppBundle appBundle;
	
	protected DataBlob blobPkcs7Signature;
	protected SuperBlob blobRequirementSet;
	protected DataBlob blobEntitlements;
	protected CodeDirectoryBlob blobCodeDirectory;
	
	protected SuperBlob blobSignature;
	
	static private int paddingByForSize(int size, int padding) {
		int mod = size % padding;

		// No padding needed
		if(mod == 0)
			return 0;

		return padding - mod;
	}
	
	public Signer(AppBundle bundle) throws Exception {
		appBundle = bundle;
		sha1 = MessageDigest.getInstance("SHA-1");
		
		// All needed blobs
		blobCodeDirectory = new CodeDirectoryBlob();
		blobEntitlements = new DataBlob(0xFADE7171);
		blobRequirementSet = new SuperBlob(0xFADE0C01);
		blobPkcs7Signature = new DataBlob(0xFADE0B01, new byte[5000]);
		
		// Application identifier
		blobCodeDirectory.identifier = bundle.identifier();
		
		// Spaceport requirement set
		blobRequirementSet.add(4, new DataBlob(0xFADE0C00, SPACEPORT_REQUIREMENTS));
		blobCodeDirectory.setHashSlot(CodeDirectoryBlob.SpecialSlot.REQUIREMENTS_SLOT, blobRequirementSet.bytes());
		
		// Final signature structure
		blobSignature = new SuperBlob(0xFADE0CC0);
		blobSignature.add(0, blobCodeDirectory);
		blobSignature.add(-CodeDirectoryBlob.SpecialSlot.REQUIREMENTS_SLOT.index, blobRequirementSet);
		blobSignature.add(-CodeDirectoryBlob.SpecialSlot.ENTITLEMENT_SLOT.index, blobEntitlements);
		blobSignature.add(0x10000, blobPkcs7Signature);
		
		// Application slot
		blobCodeDirectory.setSlot(CodeDirectoryBlob.SpecialSlot.APPLICATION_SLOT, new byte[20]);
	}
	
	public void sign(MobileProvision mobileProvision, SigningIdentity identity) throws Exception {
		if(appBundle == null)
			throw new NullPointerException("AppBundle is null");
		
		// Set Info.plist slot
		blobCodeDirectory.setHashSlot(CodeDirectoryBlob.SpecialSlot.PLISTINFO_SLOT, FileUtils.readFully(appBundle.pathForFile("Info.plist")));
		
		// Entitlements
		blobEntitlements.data = generateEntitlements(mobileProvision).getBytes("UTF8");
		blobCodeDirectory.setHashSlot(CodeDirectoryBlob.SpecialSlot.ENTITLEMENT_SLOT, blobEntitlements.bytes());
		
		RandomAccessFile executable = new RandomAccessFile(appBundle.executablePath(), "rw");

		// Pad executable to 16 (0x10)
		{
			int executableSize = (int)executable.length();
			int padding = paddingByForSize(executableSize, 16);
			
			if(padding != 0) {
				// Java does not pad with 0s when the file grows
				executable.setLength(executableSize + padding);
				// So just write 0s ourselves
				executable.seek(executableSize);
				executable.write(new byte[padding]);
				// Reset file to beginning
				executable.seek(0);
			}
		
			// Keep the executable size in the code directory
			blobCodeDirectory.codeLimit = executableSize;
		}
		
		// Fill the code directory with blank hashes for size estimate
		for(int i=0; i<(blobCodeDirectory.codeLimit/4096)+1; ++i)
			blobCodeDirectory.setSlot(i, new byte[20]);
		
		// Resource files
		{
			String resourcesSeal = generateResourceSeal();
			blobCodeDirectory.setHashSlot(CodeDirectoryBlob.SpecialSlot.RESOURCEDIR_SLOT, resourcesSeal.getBytes("UTF8"));
			
			// Create _CodeSignature directory
			{
				File csDir = new File(appBundle.bundlePath() + "/_CodeSignature");
				if(csDir.mkdir()) {
					RandomAccessFile codeRes = new RandomAccessFile(csDir.getPath() +  "/CodeResources", "rw");
					codeRes.setLength(0);
					codeRes.writeBytes(resourcesSeal);
					codeRes.close();
				} else {
					executable.close();
					throw new IllegalStateException("Failed to create _CodeSignature directory in the app bundle (Is is already signed?)");
				}
			}
		}
		
		// Build the final code directory hashset
		int unsignedSignatureBlobLength = blobSignature.bytes().length;
		unsignedSignatureBlobLength += paddingByForSize(unsignedSignatureBlobLength, 16);
		{
			// Prepare the executable for signing by attaching the header
			addSignatureHeaderToExecutable(executable, unsignedSignatureBlobLength);
			
			// Build hashes out of 
			executable.seek(0);
			int remainingSize = blobCodeDirectory.codeLimit;
			for(int i=0; i<blobCodeDirectory.codeLimit/4096+1; ++i) {
				byte[] buffer = new byte[Math.min(4096, remainingSize)];
				
				executable.readFully(buffer);
				blobCodeDirectory.setHashSlot(i, buffer);
				
				remainingSize -= 4096;
			}
		}
		
		// Generate the signature from the code directory blob
		blobPkcs7Signature.data = generatePkcs7Certificate(blobCodeDirectory.bytes(), identity);
		
		// We must keep the newly generated signature the same size as we originally declared it
		byte[] codeSignature = blobSignature.bytes();
		byte[] finalCodeSignature = new byte[unsignedSignatureBlobLength];
		System.arraycopy(codeSignature, 0, finalCodeSignature, 0, codeSignature.length);
		
		// Finally, append the signature to the executable
		executable.seek(executable.length());
		executable.write(finalCodeSignature);
		executable.close();
	}
	
	private void addSignatureHeaderToExecutable(RandomAccessFile file, int signatureSize) throws Exception {
		final int UINT32_SIZE = Integer.SIZE / 8;
		final int MACHO_HEADER_SIZE = UINT32_SIZE * 7;
		
		final int MACHO_LC_SEGMENT = 1;
		final int MACHO_LC_CODE_SIGNATURE = 29;
		
		/*
		 * This is done in 3 steps:
		 * 
		 * 1. Pad the executable to 0x10
		 * 2. Pad the VM address space of the __LINKEDIT segment
		 *    a. Re-pad segment->filesize to 16 (To match executable padding)
		 *    b. Set segment->vmsize to 4096 padding of filesize
		 * 3. Insert an LC_CODE_SIGNATURE load command
		 *    a. Add 1 to header->ncmds
		 *    b. Add sizeof(LC_CodeSignature) to sizeofcmds
		 */
		
		// Check executable exists
		if(!new File(appBundle.executablePath()).exists())
			throw new IllegalStateException("App bundle executable does not exist");
		
		FileChannel executableFC = file.getChannel();
		MappedByteBuffer executable = executableFC.map(FileChannel.MapMode.READ_WRITE, 0L, executableFC.size());
		
		// Mach-O execuables are little endians
		executable.order(ByteOrder.LITTLE_ENDIAN);
		
		// Verify executable
		if(executable.getInt(0) != 0xFEEDFACE)
			throw new IllegalStateException("Bundle executable is not a valid Mach-O executable");

		int executableSize = (int)file.length();
		
		// 1. Pad the executable to 0x10
		{
			int executablePadding = paddingByForSize(executableSize, 16);
			if(executablePadding != 0) {
				// Java does not pad with 0s when the file grows
				file.setLength(executableSize + executablePadding);
				// So just write 0s ourselves
				file.seek(executableSize);
				file.write(new byte[executablePadding]);
				// Reset file to beginning
				file.seek(0);
			}
			
			// Keep new executable size 
			executableSize += executablePadding;
		}
		
		// Header variables
		int ncmds = executable.getInt(UINT32_SIZE * 4);
		int sizeofcmds = executable.getInt(UINT32_SIZE * 5);

		// 2. Pad the VM address space of the __LINKEDIT segment
		{
			int lcPosition = MACHO_HEADER_SIZE;
			while(lcPosition < MACHO_HEADER_SIZE + sizeofcmds) {
				executable.position(lcPosition);

				int cmdtype = executable.getInt();
				int cmdsize = executable.getInt();
				
				if(cmdtype == MACHO_LC_SEGMENT) {
					byte[] segname = new byte[16];
					executable.get(segname);
					
					// "Convert" C String to java string
					String segmentName = new String(segname).replaceAll("\0*", "");
					if(segmentName.equals("__LINKEDIT")) {
						int position = executable.position();
						
						final int VMSIZE_OFFSET		= position + (UINT32_SIZE * 1);
						final int FILESIZE_OFFSET	= position + (UINT32_SIZE * 3);
						
						int filesize = executable.getInt(FILESIZE_OFFSET) + signatureSize;
						filesize += paddingByForSize(filesize, 16);
						int vmsize = filesize + paddingByForSize(filesize - signatureSize, 4096);

						executable.putInt(FILESIZE_OFFSET, filesize);
						executable.putInt(VMSIZE_OFFSET, vmsize);
					}
				}
				
				lcPosition += cmdsize;
			}
		}
		
		// 3. Insert an LC_CODE_SIGNATURE load command
		{
			int paddingNeeded = (sizeofcmds / 0x1000) + 1;
			if(((sizeofcmds + (UINT32_SIZE * 4)) / 0x1000) + 1 != paddingNeeded)
				throw new IllegalStateException("Executable repadding not supported");
			
			// Increment number of load commands and the size of all commands
			executable.putInt(UINT32_SIZE * 4, ncmds + 1);
			executable.putInt(UINT32_SIZE * 5, sizeofcmds + (UINT32_SIZE * 4));
			
			// Write out the new load command
			executable.position(MACHO_HEADER_SIZE + sizeofcmds);
			executable.putInt(MACHO_LC_CODE_SIGNATURE);
			executable.putInt(UINT32_SIZE * 4);
			executable.putInt(executableSize);
			executable.putInt(signatureSize);
		}
	}
	
	private String generateResourceSeal() throws Exception {
		NSDictionary result = (NSDictionary)PropertyListParser.parse(new File(appBundle.resourceRulesPath()));
		NSDictionary files = new NSDictionary();
		result.put("files", files);
		
		String[] bundleFiles = appBundle.resources();
		for(String fileName:bundleFiles)
			files.put(fileName, sha1.digest(FileUtils.readFully(appBundle.pathForFile(fileName))));
		
		return result.toXMLPropertyList();
	}
	
	private String generateEntitlements(MobileProvision mobileProvision) {
		return mobileProvision.getEntitlements()
			.replaceAll("\\*", appBundle.identifier())
			.replace(String.valueOf(new char[] {0x0D, 0x0A}), String.valueOf(new char[] { 0x0A }));
	}
	
	@SuppressWarnings("deprecation")
	private byte[] generatePkcs7Certificate(byte[] unsignedData, SigningIdentity identity) throws Exception {
		Provider bcProvider = new BouncyCastleProvider();
		
		// PUBLIC KEY / CERTIFICATE
		CertificateFactory x509Factory = CertificateFactory.getInstance("X.509", bcProvider);
		X509Certificate iosDeveloperCertificate = identity.getPublicKey();
		
		// CERTIFICATE CHAIN
		List<Certificate > certificateChain = new ArrayList<Certificate>();
		certificateChain.add(x509Factory.generateCertificate(getClass().getResourceAsStream("certs/AppleWWDRCA.cer")));
		certificateChain.add(x509Factory.generateCertificate(getClass().getResourceAsStream("certs/AppleIncRootCertificate.cer")));
		certificateChain.add(iosDeveloperCertificate);
		
		PrivateKey privateKey = identity.getPrivateKey();
		if(privateKey == null)
			throw new IllegalStateException("Private key not found or permission denied");
			
		CMSSignedDataGenerator signatureGenerator = new CMSSignedDataGenerator();
		signatureGenerator.addSigner(privateKey, iosDeveloperCertificate, CMSSignedDataGenerator.DIGEST_SHA1);
		signatureGenerator.addCertificates(new JcaCertStore(certificateChain));
		
		CMSProcessable content = new CMSProcessableByteArray(unsignedData);
		CMSSignedData signedData = signatureGenerator.generate(content, bcProvider);

		return signedData.getEncoded();
	}
}