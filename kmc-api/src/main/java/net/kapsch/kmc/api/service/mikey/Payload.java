package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kms.api.bouncycastle.util.Arrays;

/**
 * Class representing a MIKEY Payload of any type.
 */
public abstract class Payload {

	protected int startByte = 0;
	protected int endByte = 0;
	protected byte[] originalBytes;
	protected byte payloadType;
	/**
	 * next payload (8 bits): identifies the payload that is added after this payload.
	 */
	protected byte nextPayload = NextPayload.LAST_PAYLOAD;

	private static int hashCode(byte[] array) {
		int prime = 31;
		if (array == null) {
			return 0;
		}
		int result = 1;
		for (int index = 0; index < array.length; index++) {
			result = prime * result + array[index];
		}
		return result;
	}

	public byte[] getBytesAfterPayload() {
		return Arrays.copyOfRange(originalBytes, getEndByte(), originalBytes.length);
	}

	public void setOriginalBytes(byte[] original_bytes) {
		originalBytes = original_bytes;
	}

	public boolean hasNextPayload() {
		return nextPayload != NextPayload.LAST_PAYLOAD;
	}

	public byte getNextPayload() {
		return nextPayload;
	}

	public void setNextPayload(byte nextPayload) {
		this.nextPayload = nextPayload;
	}

	/**
	 * Encode the Payload object into a BitArray
	 *
	 * @return encoded data
	 */
	public abstract BitArray getEncoded();

	public int hashCode() {
		final int PRIME = 31;
		int result = 1;
		result = PRIME * result + getEndByte();
		result = PRIME * result + nextPayload;
		result = PRIME * result + Payload.hashCode(originalBytes);
		result = PRIME * result + startByte;
		return result;
	}

	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Payload other = (Payload) obj;
		if (nextPayload != other.nextPayload) {
			return false;
		}
		return true;
	}

	public byte getPayloadType() {
		return payloadType;
	}

	public abstract String toString();

	public int getEndByte() {
		return endByte;
	}

	public void setEndByte(int endByte) {
		this.endByte = endByte;
	}
}
