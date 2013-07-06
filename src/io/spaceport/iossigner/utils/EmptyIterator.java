package io.spaceport.iossigner.utils;

import java.util.Iterator;

/**
 * Empty iterator used when an empty collection is known at compile time
 */
public class EmptyIterator<T> implements Iterator<T> {
	@Override
	public boolean hasNext() {
		return false;
	}

	@Override
	public T next() {
		return null;
	}

	@Override
	public void remove() {
	     throw new UnsupportedOperationException();
	}
}