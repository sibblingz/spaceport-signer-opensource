package io.spaceport.iossigner.blobs;

import io.spaceport.iossigner.utils.BinaryWriter;

import java.nio.ByteOrder;
import java.util.Map;
import java.util.TreeMap;

public class SuperBlob extends Blob {
	protected TreeMap<Integer, Blob > blobs = new TreeMap<Integer, Blob>();
	
	public SuperBlob(int magic) {
		super(magic);
	}
	
	public void add(int type, Blob blob) {
		blobs.put(type, blob);
	}
	
	@Override
	protected byte[] build() {
		final int DATA_START_OFFSET = 8 + 4 + ((Integer.SIZE / 8) * 2) * blobs.size();
		
		BinaryWriter indexes = new BinaryWriter(ByteOrder.BIG_ENDIAN);
		BinaryWriter blobsData = new BinaryWriter(ByteOrder.BIG_ENDIAN);
		
		indexes.writeU32(blobs.size());
		for(Map.Entry<Integer, Blob > entry : blobs.entrySet()) {
			indexes.writeU32(entry.getKey());
			indexes.writeU32(DATA_START_OFFSET + blobsData.size());
			blobsData.writeBA(entry.getValue().bytes());
		}
		
		indexes.writeBA(blobsData.bytes());
		
		return indexes.bytes();
	}
}
