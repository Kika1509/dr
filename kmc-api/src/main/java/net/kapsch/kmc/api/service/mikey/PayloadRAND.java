package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a RAND Payload for a MIKEY-SAKKE I_MESSAGE. RFC 3830 section 6.11.
 *
 * The RAND payload consists of a (pseudo-)random bit-string. The RAND MUST be
 * independently generated per CSB (note that if the CSB has several members, the
 * Initiator MUST use the same RAND for all the members). For randomness recommendations
 * for security, see [RAND].
 */
public class PayloadRAND extends Payload {

	/* default values */
	public static final byte DEFAULT_RAND_LEN = 16;
	public static final byte RAND_DEFAULT_NEXT_PAYLOAD = NextPayload.SP;
	/**
	 * RAND len (8 bits): length of the RAND (in bytes). It SHOULD be at least 16.
	 */
	private byte randLen;
	/**
	 * RAND (variable length): a (pseudo-)randomly chosen bit-string.
	 */
	private byte[] rand;

	public PayloadRAND(final byte nextPayload, final byte randLen, final byte[] rand) {
		payloadType = NextPayload.RAND;
		this.randLen = randLen;
		this.nextPayload = nextPayload;
		this.rand = Arrays.clone(rand);
	}

	public PayloadRAND(final byte nextPayload, final byte[] rand) {
		this(nextPayload, (byte) rand.length, rand);
	}

	public PayloadRAND(final byte[] rand) {
		payloadType = NextPayload.RAND;
		this.nextPayload = RAND_DEFAULT_NEXT_PAYLOAD;
		this.randLen = (byte) rand.length;
		this.rand = Arrays.clone(rand);

		if (rand.length != (randLen & 0xFF)) {
			throw new IllegalArgumentException(
					"Given length does not meet actual length");
		}

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
	 * Decode the given byte array into a PayloadRAND object
	 *
	 * @param encoded - encoded bytes
	 * @return decoded PayloadRAND object
	 */
	public static PayloadRAND decode(final byte[] encoded) {
		byte nextPayload = encoded[0];
		byte randLen = encoded[1];
		byte[] rand;

		rand = Arrays.copyOfRange(encoded, 2, 2 + randLen);

		PayloadRAND result = new PayloadRAND(nextPayload, randLen, rand);
		result.setEndByte(2 + randLen);
		result.originalBytes = encoded;
		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);
		bits.appendBits(nextPayload, 8);
		bits.appendBits(randLen, 8);
		bits.appendBitArray(Utils.getBitsFromBytes(rand));

		return bits;
	}

	public byte getRandLen() {
		return randLen;
	}

	public byte[] getRand() {
		return rand;
	}

	@Override
	public int hashCode() {
		final int PRIME = 31;
		int result = super.hashCode();
		result = PRIME * result + PayloadRAND.hashCode(rand);
		result = PRIME * result + randLen;
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
		PayloadRAND other = (PayloadRAND) obj;
		if (!Arrays.areEqual(rand, other.rand)) {
			return false;
		}
		if (randLen != other.randLen) {
			return false;
		}
		return true;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("RAND Payload.\n");
		str.append("\tNext payload:" + nextPayload + "\n");
		str.append("\tRand len: " + randLen + "\n");
		str.append("\tRand:");
		for (int i = 0; i < rand.length; i++) {
			str.append(" " + rand[i]);
		}
		str.append("\n");
		return str.toString();
	}

}
