package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;

/**
 * Describes a MIKEY-SAKKE I_MESSAGE section of the HDR payload. See RFC 6509 section 2.1
 * for more details.
 */
public class MikeySakkeIMessage {

	/**
	 * The minimum size in bytes a Common Header Payload must be,
	 */
	public static final byte HDR_MINIMUM_SIZE_BYTES = 16;

	Payload[] payloads;

	/**
	 * Creates a MIKEY-SAKKE I_Message given an array of payloads
	 *
	 * @param payloads - payloads from which MIKEY-SAKKE I_Message will be composed
	 *
	 * @throws MikeyException - throws MikeyException exception
	 */
	public MikeySakkeIMessage(Payload[] payloads) throws MikeyException {
		if (!(payloads[0] instanceof PayloadHDR)) {
			throw new MikeyException("First payload must be a PayloadHDR.");
		}
		if (!checkOrdering(payloads)) {
			throw new MikeyException("Incorrect ordering of payloads.");
		}

		int size = payloads.length;
		this.payloads = new Payload[size];
		for (int i = 0; i < size; i++) {
			this.payloads[i] = payloads[i];
		}

	}

	/**
	 * Creates a MIKEY-SAKKE I_Message given a common header payload
	 * @param hdr - a common header payload
	 */
	public MikeySakkeIMessage(PayloadHDR hdr) {
		payloads = new Payload[] { hdr };
	}

	/**
	 * extracts the MikeySakkeIMessage object given an encoded byte array
	 *
	 * @param encoded_i_message - encoded MikeySakkeIMessage
	 * @return a decoded MikeySakkeIMessage object
	 * @throws MikeyException - throws MikeyException exception
	 */
	public static MikeySakkeIMessage decode(byte[] encoded_i_message)
			throws MikeyException {
		// Assume HDR is the first chunk of bytes
		PayloadHDR hdr = PayloadHDR.decodeHDR(encoded_i_message);
		MikeySakkeIMessage iMessage = new MikeySakkeIMessage(hdr);

		byte[] remainingBytes = hdr.getBytesAfterPayload();
		byte nextPayload = hdr.getNextPayload();

		StringBuilder str = new StringBuilder();
		while (remainingBytes.length > 0) {
			Payload next;
			try { // TODO just for testing
				next = decodePayload(remainingBytes, nextPayload);
				if (next != null) {
					str.append("Next payload decoded and adding to I Message:\n"
							+ next.toString());
					iMessage.addPayload(next);
					remainingBytes = next.getBytesAfterPayload();
					nextPayload = next.getNextPayload();
				}
			}
			catch (NullPointerException e) {
				throw new MikeyException(str.toString(), e);
			}
		}
		return iMessage;
	}

	private static Payload decodePayload(byte[] bytes, byte next) throws MikeyException {
		Payload payload = null;
		switch (next) {
		case NextPayload.CERT:
			throw new MikeyException("CERT Payloads not yet supported.");
		case NextPayload.CHASH:
			throw new MikeyException("CHASH Payloads not yet supported.");
		case NextPayload.DH:
			throw new MikeyException("DH Payloads not yet supported.");
		case NextPayload.ERR:
			throw new MikeyException("ERR Payloads not yet supported.");
		case NextPayload.GENERAL_EXT:
			payload = PayloadGeneralExtension.decode(bytes);
//			throw new MikeyException("GENERAL_EXT Payloads not yet supported.");
			break;
		case NextPayload.ID:
			throw new MikeyException("ID Payloads not yet supported.");
		case NextPayload.KEMAC:
			throw new MikeyException("KEMAC Payloads not yet supported.");
		case NextPayload.KEY_DATA:
			throw new MikeyException("KEY_DATA Payloads not yet supported.");
		case NextPayload.LAST_PAYLOAD:
			return null; // should not happen
		case NextPayload.PKE:
			throw new MikeyException("PKE Payloads not yet supported.");
		case NextPayload.RAND:
			payload = PayloadRAND.decode(bytes);
			break;
		case NextPayload.SAKKE:
			payload = PayloadSAKKE.decode(bytes);
			break;
		case NextPayload.SIGN:
			payload = PayloadSIGN.decode(bytes);
			break;
		case NextPayload.SP:
			payload = PayloadSP.decodeSP(bytes);
			break;
		case NextPayload.T:
			payload = PayloadT.decodeT(bytes);
			break;
		case NextPayload.V:
			throw new MikeyException("V Payloads not yet supported.");
		case NextPayload.IDR:
			payload = PayloadIDR.decode(bytes);
			break;
		default:
			throw new MikeyException("Unsupported payload type " + next);
		}
		return payload;
	}

	public byte[] extractIDR(int idrRole) {
		for (int i = 0; i < this.payloads.length; i++) {
			if (this.payloads[i].getPayloadType() == NextPayload.IDR) {
				if (((PayloadIDR) this.payloads[i]).getRole() == idrRole) {
					return ((PayloadIDR) this.payloads[i]).getData();
				}
			}
		}

		return null;
	}

	/**
	 * Check if the ordering of the given payloads are correct.
	 * @param payloads
	 * @return true if each payload type corresponds to the next payload attribute of the
	 * previous payload
	 */
	private boolean checkOrdering(Payload[] payloads) {
		Payload current = payloads[0];
		byte nextPayloadType;

		for (int i = 1; current.hasNextPayload() && i < payloads.length; i++) {
			nextPayloadType = current.getNextPayload();
			Payload next = payloads[i];
			if (next.getPayloadType() != nextPayloadType) {
				return false;
			}
			else {
				current = next;
			}
		}

		return true;
	}

	/**
	 * Returns the I_Message encoded as a byte array
	 *
	 * @return encoded I_Message
	 */
	public byte[] getEncoded() {
		BitArray message = new BitArray(0);

		for (int i = 0; i < payloads.length; i++) {
			message.appendBitArray(payloads[i].getEncoded());
		}

		int size = message.getSizeInBytes();
		byte[] encoded = new byte[size];
		message.toBytes(0, encoded, 0, size);

		return encoded;

	}

	/**
	 * Returns the I_Message without signature encoded as a byte array
	 *
	 * @return encoded I_Message without signature
	 */
	public byte[] getEncodedWithoutSignature() {
		BitArray message = new BitArray(0);

		for (int i = 0; i < payloads.length; i++) {
			if (!(payloads[i] instanceof PayloadSIGN)) {
				message.appendBitArray(payloads[i].getEncoded());
			}
		}

		int size = message.getSizeInBytes();
		byte[] encoded = new byte[size];
		message.toBytes(0, encoded, 0, size);

		return encoded;

	}

	/**
	 * Returns the I_Message encoded as a byte array, with the given signature appended
	 * @param signature - signature
	 * @return encoded I_Message
	 */
	public byte[] getEncoded(byte[] signature) {
		BitArray message = new BitArray(0);

		for (int i = 0; i < payloads.length; i++) {
			message.appendBitArray(payloads[i].getEncoded());
		}

		int size = message.getSizeInBytes();
		byte[] encoded = new byte[size + signature.length];
		message.toBytes(0, encoded, 0, size);

		for (int i = size; i < size + signature.length; i++) {
			encoded[i] = signature[i - size];
		}
		return encoded;
	}

	/**
	 * Add the given payload to the I_Message
	 *
	 * @param payload - given payload
	 * @throws MikeyException - throws MikeyException exception
	 */
	public void addPayload(final Payload payload) throws MikeyException {
		int payloadsLength = payloads.length;

		// Check if next payload fits.
		byte expectedType = payloads[payloadsLength - 1].getNextPayload();
		if (payload.getPayloadType() != expectedType) {
			throw new MikeyException("Next expected payload type was " + expectedType);
		}
		Payload[] newPayloads = new Payload[payloadsLength + 1];
		for (int i = 0; i < payloadsLength; i++) {
			newPayloads[i] = payloads[i];
		}
		newPayloads[payloadsLength] = payload;
		payloads = newPayloads;
	}

	public PayloadHDR getPayloadHDR() {
		Payload hdr = payloads[0];
		if (hdr instanceof PayloadHDR) {
			return (PayloadHDR) payloads[0];
		}
		else {
			return null; // should not happen
		}

	}

	public int hashCode() {
		final int PRIME = 31;
		int result = 1;
		for (int i = 0; i < payloads.length; i++) {
			result = PRIME * result
					+ ((payloads[i] == null) ? 0 : payloads[i].hashCode());
		}
		return result;
	}

	public int getNumberOfPayloads() {
		return payloads.length;
	}

	public Payload[] getPayloads() {
		return payloads;
	}

	public PayloadHDR getHDRPayload() {
		for (int i = 0; i < payloads.length; i++) {
			if (payloads[i] instanceof PayloadHDR) {
				return (PayloadHDR) payloads[i];
			}
		}

		return null;
	}

	public Payload getPayload(byte payloadType) {
		for (int i = 0; i < payloads.length; i++) {
			if (payloads[i].getPayloadType() == payloadType) {
				return payloads[i];
			}
		}

		return null;
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
		MikeySakkeIMessage other = (MikeySakkeIMessage) obj;

		// check size before checking every payload
		int size = getNumberOfPayloads();
		if (other.getNumberOfPayloads() != size) {
			return false;
		}

		for (int i = 0; i < size; i++) {
			if (!payloads[i].equals(other.getPayloads()[i])) {
				return false;
			}
		}

		return true;
	}

	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append("MIKEY-SAKKE Initialiser Message:\n");
		for (int i = 0; i < payloads.length; i++) {
			s.append("\r\n" + payloads[i].toString());
		}

		return s.toString();
	}
}
