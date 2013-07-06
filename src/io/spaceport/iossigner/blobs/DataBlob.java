package io.spaceport.iossigner.blobs;

public class DataBlob extends Blob {
	public byte[] data;
	
	public DataBlob(int magic) {
		super(magic);
	}
	
	public DataBlob(int magic, byte[] bytes) {
		super(magic);
		
		data = bytes;
	}
	
	protected byte[] build() {
		return data;
	}
}
