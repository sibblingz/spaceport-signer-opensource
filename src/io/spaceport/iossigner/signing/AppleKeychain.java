package io.spaceport.iossigner.signing;

import io.spaceport.iossigner.utils.EmptyIterator;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;

public class AppleKeychain extends SigningIdentityProvider {
	protected static char[] FAKE_KEY = "ask-user-confirmation".toCharArray();
		
	protected KeyStore keyStore = null;
	protected ArrayList<SigningIdentity> signingIdentities = new ArrayList<SigningIdentity>();
	
	protected class AppleKeychainSigningIdentity implements SigningIdentity {
		private final String alias;

		public AppleKeychainSigningIdentity(String alias) {
			this.alias = alias;
		}
		
		@Override
		public boolean isValid() {
			try {
				getPublicKey().checkValidity();
				return true;
			} catch(Exception e) {
				return false;
			}
		}

		@Override
		public X509Certificate getPublicKey() {
			try {
				return (X509Certificate)keyStore.getCertificate(alias);
			} catch (KeyStoreException e) {
				return null;
			}
		}

		@Override
		public PrivateKey getPrivateKey() {
			try {
				return (PrivateKey)keyStore.getKey(alias, FAKE_KEY);
			} catch (Exception e) {
				return null;
			}
		}

		@Override
		public String getName() {
			return alias;
		}
		
		@Override
		public boolean equals(Object other) {
			if(!(other instanceof Identity))
				return false;
			
			return ((Identity)other).getPublicKey().equals(getPublicKey());
		}
	}
	
	public AppleKeychain() {
		try {
			keyStore = KeyStore.getInstance("KeychainStore", "Apple");
			keyStore.load(null, null);
		} catch(Exception e) {
			// Any exception means we're probably not going to be able 
			// to use the keystore, just null it out and provide an empty set
			keyStore = null;
		}
		
		if(keyStore == null)
			return;
		
		try {
			// We are only interested in Key entries with 
			for(Enumeration<String> aliases=keyStore.aliases(); aliases.hasMoreElements();) {
				String alias = aliases.nextElement();
				if(!keyStore.isKeyEntry(alias))
					continue;
				
				try {
					X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
					cert.checkValidity();
					signingIdentities.add(new AppleKeychainSigningIdentity(alias));
				} catch(CertificateException e) {
					// Certificate is not yet valid or expired
					// Skip it as it is not a valid signing identity
					continue;
				} catch(KeyStoreException e) {
					// This key does not contain a certificate.
					// Skip it as it is not a signing identity.
					continue;
				}
			}
		} catch(KeyStoreException e) {
			// Error getting the aliases, ignore the keystore
			keyStore = null;
		}
	}

	public Iterator<SigningIdentity> identities() {
		if(keyStore == null)
			return new EmptyIterator<SigningIdentity>();
		
		return signingIdentities.iterator();
	}
	
	public SigningIdentity findIdentity(String name) throws IllegalArgumentException {
		if(keyStore == null)
			throw new IllegalStateException("Apple keychain not available or premission denied");
		
		for(Iterator<SigningIdentity> identities=identities(); identities.hasNext();) {
			SigningIdentity identity = identities.next();
			if(name.equals(identity.getName()))
				return identity;
		}
		
		throw new IllegalArgumentException("Name not found in local keychain");
	}
}
