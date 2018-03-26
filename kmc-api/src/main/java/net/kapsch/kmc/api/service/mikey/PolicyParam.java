package net.kapsch.kmc.api.service.mikey;

import java.util.ArrayList;

import com.google.zxing.common.BitArray;

import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Represents a Policy param part of the Security Protocol Payload. RFC 3830 section 6.10
 *
 */
public class PolicyParam {

	/**
	 * The type of the policy parameter
	 */
	private byte type;

	/**
	 * The length of the policy parameter's value in bytes
	 */
	private byte length;

	/**
	 * The value of the policy parameter
	 */
	private byte[] value;

	public PolicyParam(byte type, byte length, byte[] value) {
		if (value.length != length) {
			throw new IllegalArgumentException(
					"Given length does not match actual length.");
		}
		this.type = type;
		this.length = length;
		this.value = Arrays.copyOf(value, length);
	}

	/**
	 * Decodes the given byte array into a PolicyParam array
	 * @param encoded - encoded PolicyParam[]
	 * @param totalLen - the total length of the PolicyParam's in bytes
	 * @return - decoded PolicyParam[]
	 */
	public static PolicyParam[] decodePolicyParams(byte[] encoded, short totalLen) {
		byte type;
		byte length;
		byte[] value;
		ArrayList params = new ArrayList();
		for (int i = 0; i < totalLen; i++) {
			type = encoded[i++]; // NOSONAR
			length = encoded[i++]; // NOSONAR
			value = Arrays.copyOfRange(encoded, i, i + length);
			i = i + length - 1; // NOSONAR
			PolicyParam policyParam = new PolicyParam(type, length, value);
			params.add(policyParam);
		}

		PolicyParam[] result = new PolicyParam[params.size()];
		for (int i = 0; i < result.length; i++) {
			result[i] = (PolicyParam) params.get(i);
		}

		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray();
		bits.appendBits(type, 8);
		bits.appendBits(length, 8);
		bits.appendBitArray(Utils.getBitsFromBytes(value));
		return bits;
	}

	public byte getLength() {
		return length;
	}

	public byte getType() {
		return type;
	}

	public byte[] getValue() {
		return value;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("\ttype: " + type);
		str.append("  length: " + length);
		str.append("  value:");
		for (int i = 0; i < value.length; i++) {
			str.append(" " + value[i]);
		}
		str.append("\n");
		return str.toString();
	}
}
