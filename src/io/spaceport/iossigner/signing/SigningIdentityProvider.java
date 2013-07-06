package io.spaceport.iossigner.signing;

import java.util.Iterator;

public abstract class SigningIdentityProvider extends IdentityProvider {
	@Override
	public abstract Iterator<? extends SigningIdentity> identities();
}
