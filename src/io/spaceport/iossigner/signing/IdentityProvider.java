package io.spaceport.iossigner.signing;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

public abstract class IdentityProvider {
	/**
	 * Class intended to intersect between two providers and only provide the shared identities 
	 */
	protected static class IntersectionIdentityProvider extends IdentityProvider {
		Collection<Identity> intersection = new HashSet<Identity>();
		
		public IntersectionIdentityProvider(IdentityProvider first, IdentityProvider second) {
			for(Iterator<? extends Identity> firstIterator=first.identities(); firstIterator.hasNext();) {
				Identity firstValue = firstIterator.next();
				for(Iterator<? extends Identity> secondIterator=second.identities(); secondIterator.hasNext();) {
					Identity secondValue = secondIterator.next();
					if(firstValue.getPublicKey().equals(secondValue.getPublicKey()))
						intersection.add(secondValue);
				}
			}
		}
		
		@Override
		public Iterator<? extends Identity> identities() {
			return intersection.iterator();
		}
	}
	
	/**
	 * Iterate over all identities provided by this provider
	 */
	public abstract Iterator<? extends Identity> identities();
	
	/**
	 * Checks if identity is provided by this {@link IdentityProvider}
	 */
	public boolean containsIdentity(Identity ident) {
		for(Iterator<? extends Identity> identity=identities(); identity.hasNext();) {
			if(identity.next().getPublicKey().equals(ident.getPublicKey()))
				return true;
		}
		
		return false;
	}
	
	/**
	 * Retrieves a new provider that only gives the intersection of this and other
	 */
	public IdentityProvider intersection(IdentityProvider other) {
		return new IntersectionIdentityProvider(this, other);
	}
}
