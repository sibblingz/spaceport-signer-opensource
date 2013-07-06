package io.spaceport.iossigner.utils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteOrder;

public class BinaryWriter {
	protected ByteOrder byteOrder = ByteOrder.nativeOrder();
	
	protected ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	protected DataOutputStream writer = new DataOutputStream(buffer);
	
	public BinaryWriter() {
		// Empty constructor
	}

	public BinaryWriter(ByteOrder bo) {
		byteOrder = bo;
	}
	
	public int size() {
		return buffer.size();
	}
	
	public byte[] bytes() {
		return buffer.toByteArray();
	}
	
	public void writeU8(int value) {
		writeU8((byte)value);
	}
	
	public void writeU8(byte value) {
		try {
			writer.writeByte(value);
		} catch (Exception e) {
			// ByteArrayOutputStream always succeeds
		}
	}
	
	public void writeU16(short value) {
		if(byteOrder == ByteOrder.LITTLE_ENDIAN) {
			writeU8((byte)(value >>> 0));
			writeU8((byte)(value >>> 8));
		}
		if(byteOrder == ByteOrder.BIG_ENDIAN) {
			writeU8((byte)(value >>> 8));
			writeU8((byte)(value >>> 0));
		}
	}
	
	public void writeU32(int value) {
		if(byteOrder == ByteOrder.LITTLE_ENDIAN) {
			writeU16((short)(value >>>  0));
			writeU16((short)(value >>> 16));
		}
		if(byteOrder == ByteOrder.BIG_ENDIAN) {
			writeU16((short)(value >>> 16));
			writeU16((short)(value >>>  0));
		}
	}
	
	public void writeBA(byte[] ba) {
		try {
			writer.write(ba);
		} catch (IOException e) {
			// ByteArrayOutputStream always succeeds
		}
	}
	
	public void writeString(String string) {
		try {
			writer.writeBytes(string);
			writer.writeByte(0);
		} catch(IOException e) {
			// ByteArrayOutputStream always succeeds
		}
	}
}
