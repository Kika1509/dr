package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes an IDR Payload for a MIKEY-SAKKE I_MESSAGE. RFC 3830 section 6.7.
 *
 * The ID payload carries a uniquely-defined identifier. The IDR payload uses all the
 * fields from the standard identity payload (ID) but expands it with a new field
 * describing the role of the ID payload. Whereas the ID Type describes the type of the ID
 * Data, the ID Role describes the meaning of the identity itself. The IDR payload is
 * intended to eliminate ambiguity when a MIKEY message contains several identity
 * payloads. The IDR payload MUST be used instead of the ID payload in all MIKEY-TICKET
 * messages.
 */
public class PayloadIDR extends Payload {

	/**
	 * ID Role: specifies the sort of identity
	 */
	private byte idRole;
	/**
	 * ID Type: specifies the identifier type used.
	 */
	private byte idType;

	/**
	 * ID len: The length of the ID or Certificate field (in bytes).
	 */
	private short idLen;

	/**
	 * The ID data
	 */
	private byte[] idData;

	public PayloadIDR(final byte nextPayload, final byte idRole, final byte idType,
			final short idLen, final byte[] idData) {
		if (idData.length != idLen) {
			throw new IllegalArgumentException(
					"Given length does not match actual length of data.");
		}
		payloadType = NextPayload.IDR;
		this.idRole = idRole;
		this.nextPayload = nextPayload;
		this.idType = idType;
		this.idLen = idLen;
		this.idData = idData;
	}

	public PayloadIDR(final byte nextPayload, final byte idRole, final byte idType,
			final byte[] idData) {
		this(nextPayload, idRole, idType, (short) idData.length, idData);
	}

	/**
	 * Decode the given byte array into a PayloadIDR object
	 *
	 * @param encoded - encoded bytes
	 * @return decoded PayloadIDR object
	 */
	public static PayloadIDR decode(final byte[] encoded) {
		byte nextPayload = encoded[0];
		byte role = encoded[1];
		byte type = encoded[2];
		byte[] lenBytes = Arrays.copyOfRange(encoded, 3, 5);
		short len = Utils.convertByteArrayToShort(lenBytes);
		byte[] data;

		data = Arrays.copyOfRange(encoded, 5, 5 + len);

		PayloadIDR result = new PayloadIDR(nextPayload, role, type, len, data);
		result.setEndByte(5 + len);
		result.originalBytes = encoded;
		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);
		bits.appendBits(nextPayload, 8);
		bits.appendBits(idRole, 8);
		bits.appendBits(idType, 8);
		bits.appendBits(idLen, 16);
		bits.appendBitArray(Utils.getBitsFromBytes(idData));

		return bits;
	}

	public byte getRole() {
		return idRole;
	}

	public byte[] getData() {
		return idData;
	}

	public byte getType() {
		return idType;
	}

	public short getIdLen() {
		return idLen;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("IDR Payload.\n");
		str.append("\tNext payload:" + nextPayload + "\n");
		str.append("\tRole: " + idRole + "\n");
		str.append("\tType: " + idType + "\n");
		str.append("\tID length: " + idLen + "\n");
		str.append("\tID data:");
		for (int i = 0; i < idData.length; i++) {
			str.append(" " + idData[i]);
		}
		str.append("\n");
		return str.toString();
	}

}
