package io.spaceport.iossigner.signing;

import io.spaceport.iossigner.utils.EmptyIterator;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Pkcs12SigningIdentity extends SigningIdentityProvider implements SigningIdentity {
	protected static final char[] FAKE_PASSWORD = "fake-password".toCharArray();
	protected static final Provider bcProvider = new BouncyCastleProvider();
	
	protected KeyStore keyStore;
	protected String identityAlias;

	public Pkcs12SigningIdentity(InputStream pkcs12, String password) throws IOException, CertificateException, IllegalArgumentException {
		if(password == null)
			password = "";
		
		try {
			keyStore = KeyStore.getInstance("PKCS12", bcProvider);
			keyStore.load(pkcs12, password.toCharArray());
			
			List<String> aliases = Collections.list(keyStore.aliases());
			for(String alias : aliases) {
				if(!keyStore.isKeyEntry(alias))
					continue;
				
				if(identityAlias != null)
					throw new IllegalArgumentException("Multiple identities are not supported");
				
				identityAlias = alias;
			}
			
			if(identityAlias == null)
				throw new IllegalArgumentException("PKCS12 does not contain a private key");
		} catch(NoSuchAlgorithmException e) {
			keyStore = null;
		} catch(KeyStoreException e) {
			keyStore = null;
		}
	}
	
	@Override
	public boolean isValid() {
		if(keyStore == null)
			return false;
		
		try {
			getPublicKey().checkValidity();
			return true;
		} catch(Exception e) {
			return false;
		}
	}

	@Override
	public String getName() {
		return identityAlias;
	}

	@Override
	public X509Certificate getPublicKey() {
		try {
			return (X509Certificate)keyStore.getCertificate(identityAlias);
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public PrivateKey getPrivateKey() {
		try {
			return (PrivateKey)keyStore.getKey(identityAlias, FAKE_PASSWORD);
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public Iterator<? extends SigningIdentity> identities() {
		if(keyStore == null)
			return new EmptyIterator<SigningIdentity>();
		
		return Collections.singleton(this).iterator();
	}

	@Override
	public boolean equals(Object other) {
		if(!(other instanceof Identity))
			return false;
		
		return ((Identity)other).getPublicKey().equals(getPublicKey());
	}
}
