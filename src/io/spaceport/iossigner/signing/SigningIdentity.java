package io.spaceport.iossigner.signing;

import java.security.PrivateKey;

public interface SigningIdentity extends Identity {
	PrivateKey getPrivateKey();
}
