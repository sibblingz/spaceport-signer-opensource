package io.spaceport.iossigner.signing;

import java.security.cert.X509Certificate;

public interface Identity {
	boolean isValid();
	
	String getName();
	
	X509Certificate getPublicKey();
}
