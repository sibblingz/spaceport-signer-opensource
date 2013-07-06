package io.spaceport.iossigner.signing;

import io.spaceport.iossigner.utils.EmptyIterator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.dd.plist.NSArray;
import com.dd.plist.NSData;
import com.dd.plist.NSDate;
import com.dd.plist.NSDictionary;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;

/*
 * A mobile provisioning profile is actually a signed plist from apple.
 * 
 * The mobile provisioning profile contains:
 * 	- Application ID name (AppIDName => String)
 * 	- Application identifier prefix (ApplicationIdentifierPrefix => Array<String >)
 *  - Creation date (CreationDate => Date)
 *  - Certificates with public identities (DeveloperCertificates => Array<byte[] >)
 *  - Entitlements template (Entitlements => NSDictionary)
 *  - Expiration Date (ExpirationDate => Date)
 *  - Provision name template (Name => String)
 *  - A list of provisioned device IDs (ProvisionedDevices => Array<String >)
 *  - Team publishing identifier (TeamIdentifier => Array<String >)
 *  - Number of days from creation date to expiry (TimeToLive => Integer)
 *  - UUID and Version (unknown)
 */
public class MobileProvision extends IdentityProvider {
	protected static Provider bcProvider = new BouncyCastleProvider();
	
	/**
	 * A developer identity from a MobileProvision instance
	 */
	protected static class DeveloperIdentity implements Identity {
		protected X509Certificate certificate;

		public DeveloperIdentity(NSData certificateData) {
			try {
				CertificateFactory x509Factory = CertificateFactory.getInstance("X.509");
				certificate = (X509Certificate)x509Factory.generateCertificate(new ByteArrayInputStream(certificateData.bytes()));
			} catch(CertificateException e) {
				throw new IllegalArgumentException("Not an X.509 certificate", e);
			}
		}
		
		@Override
		public boolean isValid() {
			try {
				certificate.checkValidity();
			} catch (CertificateExpiredException e) {
				return false;
			} catch(CertificateNotYetValidException e) {
				return false;
			}
			
			return true;
		}

		@Override
		public X509Certificate getPublicKey() {
			return certificate;
		}

		@Override
		public String getName() {
			return certificate.getSubjectDN().getName();
		}
		
		@Override
		public boolean equals(Object other) {
			if(!(other instanceof Identity))
				return false;
			
			return certificate.equals(((Identity)other).getPublicKey());
		}
	}
	
	/**
	 * Iterator that returns a DeveloperIdentity from an NSArray that
	 * originated from a MobileProvision
	 */
	protected static class DeveloperIdentityIterator implements Iterator<Identity> {
		private int currentIndex;
		private NSArray certificates;

		public DeveloperIdentityIterator(NSArray developerCertificates) {
			currentIndex = 0;
			certificates = developerCertificates;
		}
		
		@Override
		public boolean hasNext() {
			return currentIndex < certificates.count();
		}

		@Override
		public Identity next() {
			if(currentIndex >= certificates.count())
				throw new NoSuchElementException();
			
			return new DeveloperIdentity((NSData)certificates.objectAtIndex(currentIndex++));
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}
	
	protected CMSSignedData signedBlob;
	protected NSDictionary signedPlist;
	
	public MobileProvision(InputStream data) throws IllegalArgumentException {
		try {
			signedBlob = new CMSSignedData(data);
			signedPlist = (NSDictionary)PropertyListParser.parse((byte[])signedBlob.getSignedContent().getContent());
		} catch(Exception e) {
			throw new IllegalArgumentException("Not a mobile provision profile" , e);
		}
	}
	
	public Iterator<Identity> identities() {
		NSObject developerCertificate = signedPlist.objectForKey("DeveloperCertificates");
		if(developerCertificate == null)
			return new EmptyIterator<Identity>();
		
		return new DeveloperIdentityIterator(((NSArray)developerCertificate));
	}
	
	public boolean isValid() {
		Date today = new Date();
		if(today.after(validBefore()))
			return false;
		
		// XXX: BouncyCastle is too damn hard, do signature verification later
		return true;
	}
	/**
	 * Warning: This may not be accurate and should be treated as a guess.
	 */
	public boolean isRelease() {
		// TODO: There are probably more signs
		return signedPlist.objectForKey("ProvisionedDevices") == null;
	}
	
	/**
	 * Returns the entitlements plist
	 */
	public String getEntitlements() {
		return signedPlist.objectForKey("Entitlements").toXMLPropertyList();
	}
	
	/**
	 * Returns the date where this provisioning profile stops being valid
	 */
	public Date validBefore() {
		return ((NSDate)signedPlist.objectForKey("ExpirationDate")).getDate();
	}
	
	/**
	 * Get the name as specified in the provisioning profile
	 */
	public String getName() {
		return signedPlist.objectForKey("Name").toString();
	}
	
	/**
	 * Get the application identifier as specified in the provisioning profile
	 */
	public String getApplicationIdentifier() {
		return ((NSDictionary)signedPlist.objectForKey("Entitlements")).objectForKey("application-identifier").toString();
	}

	/**
	 * Get a list of provisioned devices uuids 
	 */
	public Collection<String> getProvisionedDevices() {
		NSArray devices = ((NSArray)signedPlist.objectForKey("ProvisionedDevices"));
		if(devices == null)
			return new ArrayList<String>();
		
		NSObject[] uuids = devices.getArray();

		ArrayList<String> result = new ArrayList<String>();
		for(NSObject uuid : uuids)
			result.add(uuid.toString());
		
		return result;
	}

	/**
	 * Write the provisioning profile to a file
	 */
	public void writeTo(File file) throws IOException {
		FileOutputStream out = null;
		try {
			out = new FileOutputStream(file);
			out.write(signedBlob.getEncoded());
		} finally {
			try {
				if(out != null)
					out.close();
			} catch(IOException e) {
				// Don't know what to do in case closing fails.
			}
		}
	}
}
