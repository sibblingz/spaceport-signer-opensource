package io.spaceport.iossigner.blobs;

import io.spaceport.iossigner.utils.BinaryWriter;

import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

public class CodeDirectoryBlob extends Blob {
	public enum SpecialSlot {
		PLISTINFO_SLOT		(-1),
		REQUIREMENTS_SLOT	(-2),
		RESOURCEDIR_SLOT	(-3),
		APPLICATION_SLOT	(-4),
		ENTITLEMENT_SLOT	(-5);
		
		public final int index;
		
		SpecialSlot(int slotIndex) {
			index = slotIndex;
		}
	}
	
	public int codeLimit = 0;
	public String identifier = "";
	public TreeMap<Integer, byte[] > hashSlots = new TreeMap<Integer, byte[] >();
	
	private MessageDigest sha1;
	
	public CodeDirectoryBlob() {
		super(0xFADE0C02);
		
		try {
			sha1 = MessageDigest.getInstance("SHA-1");
		} catch(NoSuchAlgorithmException e) {
			// Something's really fucked up at this point...
		}
	}
	
	/**
	 * Directly place hash in special slots
	 */
	public void setSlot(Integer slot, byte[] bytes) {
		hashSlots.put(slot, bytes);
	}

	/**
	 * Directly place hash in special slots
	 */
	public void setSlot(SpecialSlot slot, byte[] bytes) {
		hashSlots.put(slot.index, bytes);
	}

	/**
	 * Hash slot data
	 */
	public void setHashSlot(Integer slot, byte[] bytes) {
		setSlot(slot, sha1.digest(bytes));
	}

	public void setHashSlot(SpecialSlot slot, byte[] bytes) {
		setSlot(slot, sha1.digest(bytes));
	}
	
	@Override
	protected byte[] build() {
		final int nSpecialSlots = countSpecialSlots();
		final int nCodeSlots = hashSlots.size() - nSpecialSlots;
		
		final int dataOffset = (Integer.SIZE / 8) * (10 + 2);
		
		final int hashSize = 20;
		final int hashOffset = dataOffset + (identifier.length() + 1) + (nSpecialSlots * hashSize);
		
		BinaryWriter writer = new BinaryWriter(ByteOrder.BIG_ENDIAN);
		writer.writeU32(0x00020100);	// Version (2.1)
		writer.writeU32(0x00000000);	// Flags (none)
		writer.writeU32(hashOffset);	// Offset of hash array at index 0
		writer.writeU32(dataOffset);	// Binary identifier offset
		writer.writeU32(nSpecialSlots);	// Number of special slots (negative indexes)
		writer.writeU32(nCodeSlots);	// Number of 'code slots' (number of 4096b blocks in binary)
		writer.writeU32(codeLimit);		// Size of binary
		
		writer.writeU8(hashSize);		// Hash size (20 bytes, SHA1)
		writer.writeU8(1);				// Hash type (SHA1)
		writer.writeU8(0);				// RESERVED
		writer.writeU8(12);				// Page size (1 << 12 = 4096)

		writer.writeU32(0);				// RESERVED
		writer.writeU32(0);				// scatter (unsupported)

		writer.writeString(identifier);
		for(Map.Entry<Integer, byte[] > slot : hashSlots.entrySet())
			writer.writeBA(slot.getValue());
		
		return writer.bytes();
	}
	
	private int countSpecialSlots() {
		int result = 0;
		for(Map.Entry<Integer, byte[] > slot : hashSlots.entrySet()) {
			if(slot.getKey() < 0)
				result += 1;
		}
		
		return result;
	}
}
