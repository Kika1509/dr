package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kmc.api.service.mikey.tables.TSType;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a Timestamp Payload for a MIKEY-SAKKE I_MESSAGE. RFC 3830 section 6.6
 *
 * The timestamp payload carries the timestamp information.
 */
public class PayloadT extends Payload {

	/* Default values */
	public static final byte DEFAULT_TS_TYPE = TSType.NTP_UTC;
	public static final byte T_DEFAULT_NEXT_PAYLOAD = NextPayload.RAND;
	byte tsType;
	byte[] tsValue;

	/**
	 * Creates PayloadT object with given parameters
	 *
	 * @param nextPayload - nextpayload type
	 * @param tsType - time stamp type
	 * @param tsValue - timestamp value
	 */
	public PayloadT(final byte nextPayload, final byte tsType, final byte[] tsValue) {
		payloadType = NextPayload.T;
		this.tsType = tsType;
		this.tsValue = tsValue;
		this.nextPayload = nextPayload;
	}

	/**
	 * Creates PayloadT object with given parameters
	 *
	 * @param nextPayload - nextpayload type
	 * @param tsType - time stamp type
	 * @param tsValue - timestamp value
	 */
	public PayloadT(final byte nextPayload, final byte tsType, final long tsValue) {
		payloadType = NextPayload.T;
		this.tsType = tsType;
		this.tsValue = Utils.longToBytes(tsValue);
		this.nextPayload = nextPayload;
	}

	/**
	 * Creates PayloadT object with default values
	 *
	 * @param tsValue - byte array representing the timestamp
	 */
	public PayloadT(final long tsValue) {
		payloadType = NextPayload.T;
		tsType = DEFAULT_TS_TYPE;
		nextPayload = T_DEFAULT_NEXT_PAYLOAD;
		this.tsValue = Utils.longToBytes(tsValue);
	}

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

	/**
	 * decodes the given byte array into a PayloadT object
	 *
	 * @param encoded - byte array to decode
	 * @return decoded PayloadT object
	 */
	public static PayloadT decodeT(final byte[] encoded) {
		byte next = encoded[0];
		byte type = encoded[1];

		byte ts_len = 0;

		switch (type) {
		case TSType.NTP_UTC:
			ts_len = 64 / 8;
			break;
		case TSType.NTP:
			ts_len = 64 / 8;
			break;
		case TSType.NTP_UTC_32:
			ts_len = 32 / 8;
			break;
		case TSType.COUNTER:
			ts_len = 32 / 8;
			break;
		default:
			break;
		}

		byte[] ts = Arrays.copyOfRange(encoded, 2, 2 + ts_len);

		PayloadT result = new PayloadT(next, type, ts);
		result.setEndByte(2 + ts_len);
		result.originalBytes = encoded;
		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);
		bits.appendBits(nextPayload, 8);
		bits.appendBits(tsType, 8);
		bits.appendBitArray(Utils.getBitsFromBytes(tsValue));
		return bits;
	}

	public byte getTsType() {
		return tsType;
	}

	public byte[] getTsValue() {
		return tsValue;
	}

	@Override
	public int hashCode() {
		final int PRIME = 31;
		int result = super.hashCode();
		result = PRIME * result + tsType;
		result = PRIME * result + PayloadT.hashCode(tsValue);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PayloadT other = (PayloadT) obj;
		if (tsType != other.tsType) {
			return false;
		}
		if (!Arrays.areEqual(tsValue, other.tsValue)) {
			return false;
		}
		return true;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("Timestamp Payload.\n");
		str.append("\tNext payload: " + nextPayload + "\n");
		str.append("\tTS type: " + tsType + "\n");
		str.append("\tTS value:");
		for (int i = 0; i < tsValue.length; i++) {
			str.append(" " + tsValue[i]);
		}
		str.append("\n");
		return str.toString();
	}
}
