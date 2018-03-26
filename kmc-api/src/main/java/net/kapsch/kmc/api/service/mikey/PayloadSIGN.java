package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kmc.api.service.mikey.tables.SType;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a SIGN Payload for a MIKEY-SAKKE I_MESSAGE. RFC 3830 section 6.5.
 *
 * The Signature payload carries the signature and its related data. The signature payload
 * is always the last payload in the PK transport and DH exchange messages. The signature
 * algorithm used is implicit from the certificate/public key used.
 */
public class PayloadSIGN extends Payload {

	/* default values */
	public static final byte DEFAULT_S_TYPE = SType.ECCSI;
	public static final short DEFAULT_SIGNATURE_LEN = 129;
	public static final byte SIGN_DEFAULT_NEXT_PAYLOAD = NextPayload.LAST_PAYLOAD; // not
	/**
	 * S type (4 bits): indicates the signature algorithm applied by the signer.
	 */
	byte sType;
	// required
	/**
	 * Signature len (12 bits): the length of the signature field (in bytes
	 */
	short signatureLen;
	/**
	 * Signature (variable length): the signature (its formatting and padding depend on
	 * the type of signature).
	 */
	byte[] signature;

	public PayloadSIGN(final byte type, final short len, final byte[] sig) {
		if ((0xff & len) != sig.length) {
			throw new IllegalArgumentException(
					"Given length does not match actual length");
		}
		payloadType = NextPayload.SIGN;
		sType = type;
		signatureLen = len;
		signature = sig;
	}

	public PayloadSIGN(final byte type, final byte[] sig) {
		this(type, (short) sig.length, sig);
	}

	public PayloadSIGN(final byte[] signature) {
		payloadType = NextPayload.SIGN;
		sType = DEFAULT_S_TYPE;
		this.signature = signature;
		signatureLen = (short) signature.length;
		if (signatureLen != DEFAULT_SIGNATURE_LEN) {
			throw new IllegalArgumentException(
					"Signature length must be " + DEFAULT_SIGNATURE_LEN);
		}
	}

	public PayloadSIGN() {
		payloadType = NextPayload.SIGN;
		sType = DEFAULT_S_TYPE;
		signatureLen = DEFAULT_SIGNATURE_LEN;
		signature = new byte[0];
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
	 * decodes the given array into a PayloadSIGN object
	 *
	 * @param encoded - the encoded data
	 * @return - decoded PayloadSIGN
	 */
	public static PayloadSIGN decode(final byte[] encoded) {
		PayloadSIGN result = null;
		if (encoded != null && encoded.length >= 2) {

			// First 4 bits is S type, next 12 is signature length
			byte[] first_two = Arrays.copyOfRange(encoded, 0, 2);
			short s_type_and_len = Utils.convertByteArrayToShort(first_two);
			// bit shift 12 to get first 4 bits
			short s_type_short = (short) (s_type_and_len >>> 12);
			byte s_type = (byte) s_type_short;
			// bitmask 0xFFF to get rid of first 4 bits
			short len = (short) (s_type_and_len & 0xfff);
			byte[] signature;
			signature = Arrays.copyOfRange(encoded, 2, 2 + len);

			result = new PayloadSIGN(s_type, len, signature);
			result.setEndByte(2 + len);
			result.originalBytes = encoded;
		}

		return result;

	}

	public BitArray getEncoded() {

		BitArray bits = new BitArray(0);

		bits.appendBits(sType, 4);
		bits.appendBits(signatureLen, 12);
		bits.appendBitArray(Utils.getBitsFromBytes(signature));

		return bits;
	}

	public byte getsType() {
		return sType;
	}

	public short getSignatureLen() {
		return signatureLen;
	}

	public byte[] getSignature() {
		return signature;
	}

	@Override
	public int hashCode() {
		final int PRIME = 31;
		int result = super.hashCode();
		result = PRIME * result + sType;
		result = PRIME * result + PayloadSIGN.hashCode(signature);
		result = PRIME * result + signatureLen;
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
		PayloadSIGN other = (PayloadSIGN) obj;
		if (sType != other.sType) {
			return false;
		}
		if (!Arrays.areEqual(signature, other.signature)) {
			return false;
		}
		if (signatureLen != other.signatureLen) {
			return false;
		}
		return true;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("SIGN Payload.\n");
		str.append("\tNext payload: " + nextPayload + "\n");
		str.append("\tS type: " + sType + "\n");
		str.append("\tSignature:");
		for (int i = 0; i < signature.length; i++) {
			str.append(" " + signature[i]);
		}
		str.append("\n");
		return str.toString();
	}

}
