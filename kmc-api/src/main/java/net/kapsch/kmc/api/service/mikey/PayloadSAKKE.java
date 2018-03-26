package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a SAKKE Payload for a MIKEY-SAKKE I_MESSAGE. RFC 6509 section 4.2.
 *
 * The SAKKE payload contains the SAKKE Encapsulated Data as defined in [RFC6508].
 *
 *
 */
public class PayloadSAKKE extends Payload {

	/* default values */
	public static final byte DEFAULT_SAKKE_PARAMS = 1;
	public static final byte SAKKE_DEFAULT_NEXT_PAYLOAD = NextPayload.SIGN;
	public static final byte DEFAULT_ID_SCHEME = 1; // tel URI with monthly keys
	public static final short DEFAULT_SAKKE_DATA_LEN = 273;
	/**
	 * SAKKE params (8 bits): indicates the SAKKE parameter set to be used.
	 */
	private byte sakkeParams;
	/**
	 * ID scheme (8 bits): indicates the SAKKE identifier scheme to be used.
	 */
	private byte idScheme;
	/**
	 * SAKKE data length (16 bits): length of SAKKE data (in bytes).
	 */
	private short sakkeDataLen;
	/**
	 * SAKKE data (variable): the SAKKE Encapsulated Data formatted as defined in Section
	 * 4 of [RFC6508]
	 */
	private byte[] sakkeData;

	public PayloadSAKKE(final byte nextPayload, final byte sakkeParams,
			final byte idScheme, final short sakkeDataLen, final byte[] sakkeData) {

		if (sakkeDataLen != sakkeData.length) {
			throw new IllegalArgumentException(
					"Given length does not match actual length");
		}
		payloadType = NextPayload.SAKKE;
		this.nextPayload = nextPayload;
		this.sakkeParams = sakkeParams;
		this.idScheme = idScheme;
		this.sakkeDataLen = sakkeDataLen;
		this.sakkeData = Arrays.clone(sakkeData);
	}

	public PayloadSAKKE(final byte nextPayload, final byte sakkeParams,
			final byte idScheme, final byte[] sakkeData) {

		this(nextPayload, sakkeParams, idScheme, (short) sakkeData.length, sakkeData);
	}

	public PayloadSAKKE(final byte[] sakkeData) {
		if (sakkeData.length != DEFAULT_SAKKE_DATA_LEN) {
			throw new IllegalArgumentException(
					"SAKKE Encapsulated Data length must be " + DEFAULT_SAKKE_DATA_LEN);
		}
		payloadType = NextPayload.SAKKE;
		nextPayload = SAKKE_DEFAULT_NEXT_PAYLOAD;
		sakkeParams = DEFAULT_SAKKE_PARAMS;
		idScheme = DEFAULT_ID_SCHEME;
		sakkeDataLen = DEFAULT_SAKKE_DATA_LEN;
		this.sakkeData = Arrays.clone(sakkeData);
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
	 * Decode the given byte array into a PayloadSAKKE object
	 *
	 * @param encoded - encoded bytes
	 * @return decoded PayloadSAKKE object
	 */
	public static PayloadSAKKE decode(final byte[] encoded) {
		byte next_payload = encoded[0];
		byte sakke_params = encoded[1];
		byte id_scheme = encoded[2];
		byte[] data_len_array = { encoded[3], encoded[4] };
		short data_length = Utils.convertByteArrayToShort(data_len_array);

		byte[] rand;

		rand = Arrays.copyOfRange(encoded, 5, 5 + data_length);

		PayloadSAKKE result = new PayloadSAKKE(next_payload, sakke_params, id_scheme,
				data_length, rand);
		result.setEndByte(5 + data_length);
		result.originalBytes = encoded;
		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);

		bits.appendBits(nextPayload, 8);
		bits.appendBits(sakkeParams, 8);
		bits.appendBits(idScheme, 8);
		bits.appendBits(sakkeDataLen, 16);
		bits.appendBitArray(Utils.getBitsFromBytes(sakkeData));

		return bits;
	}

	public byte getSakkeParams() {
		return sakkeParams;
	}

	public byte getIdScheme() {
		return idScheme;
	}

	public short getSakkeDataLen() {
		return sakkeDataLen;
	}

	public byte[] getSakkeData() {
		return sakkeData;
	}

	@Override
	public int hashCode() {
		final int PRIME = 31;
		int result = super.hashCode();
		result = PRIME * result + idScheme;
		result = PRIME * result + PayloadSAKKE.hashCode(sakkeData);
		result = PRIME * result + sakkeDataLen;
		result = PRIME * result + sakkeParams;
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
		PayloadSAKKE other = (PayloadSAKKE) obj;
		if (idScheme != other.idScheme) {
			return false;
		}
		if (!Arrays.areEqual(sakkeData, other.sakkeData)) {
			return false;
		}
		if (sakkeDataLen != other.sakkeDataLen) {
			return false;
		}
		if (sakkeParams != other.sakkeParams) {
			return false;
		}
		return true;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("SAKKE Payload.\n");
		str.append("\tNext payload: " + nextPayload + "\n");
		str.append("\tSAKKE params: " + sakkeParams + "\n");
		str.append("\tID scheme: " + idScheme + "\n");
		str.append("\tSAKKE data length: " + sakkeDataLen + "\n");
		str.append("\tSAKKE data:");
		for (int i = 0; i < sakkeData.length; i++) {
			str.append(" " + sakkeData[i]);
		}
		str.append("\n");
		return str.toString();
	}

}
