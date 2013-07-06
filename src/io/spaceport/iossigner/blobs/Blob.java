package io.spaceport.iossigner.blobs;

import io.spaceport.iossigner.utils.BinaryWriter;

import java.nio.ByteOrder;

public abstract class Blob {
	protected int magic; 
	
	public Blob(int magic) {
		this.magic = magic;
	}
	
	public byte[] bytes() {
		byte[] data = build();
		
		BinaryWriter writer = new BinaryWriter(ByteOrder.BIG_ENDIAN);
		writer.writeU32(magic);
		writer.writeU32(data.length + ((Integer.SIZE / 8) * 2));
		writer.writeBA(data);
		
		return writer.bytes();
	}
	
	protected abstract byte[] build();
}
