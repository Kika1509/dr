package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kmc.api.service.mikey.tables.ProtType;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a Security Policy Payload for a MIKEY-SAKKE I_MESSAGE. RFC 3830 section 6.10.
 *
 * The Security Policy payload defines a set of policies that apply to a specific security
 * protocol.
 */
public class PayloadSP extends Payload {

	public static final byte SP_DEFAULT_NEXT_PAYLOAD = NextPayload.SAKKE;

	/**
	 * Policy no (8 bits): each security policy payload must be given a distinct number
	 * for the current MIKEY session by the local peer. This number is used to map a
	 * crypto session to a specific policy (see also Section 6.1.1).
	 */
	private byte policyNo;

	/**
	 * Prot type (8 bits): defines the security protocol.
	 */
	private byte protType;

	/**
	 * Policy param length (16 bits): defines the total length of the policy parameters
	 * for the specific security protocol.
	 */
	private short policyParamLen;

	/**
	 * Policy param (variable length): defines the policy for the specific security
	 * protocol.
	 */
	private PolicyParam[] policyParams;

	public PayloadSP(final byte nextPayload, final byte policyNo, final byte protType,
			final short policyParamLen, final PolicyParam[] policyParam) {

		if (!checkLengthsOk(policyParamLen, policyParam)) {
			throw new IllegalArgumentException(
					"Given length does not match actual length.");
		}
		this.payloadType = NextPayload.SP;
		this.nextPayload = nextPayload;
		this.policyNo = policyNo;
		this.protType = protType;
		this.policyParamLen = policyParamLen;
		this.policyParams = policyParam;
	}

	public PayloadSP(PolicyParam[] policyParams, short policyParamLen) {
		this(policyParamLen, policyParams);
	}

	public PayloadSP(short policyParamLen, PolicyParam[] policyParam) {
		this(SP_DEFAULT_NEXT_PAYLOAD, (byte) 1, ProtType.SRTP, policyParamLen,
				policyParam);
	}

	public static short calculateLength(PolicyParam[] policyParams) {
		short length = 0;
		for (PolicyParam policy : policyParams) {
			length += policy.getLength() + 2;
		}
		return length;
	}

	/**
	 * Decodes the given byte array into a PayloadSP
	 * @param encoded - encoded PayloadSPdecoded
	 * @return - decoded PayloadSPdecoded
	 */
	public static PayloadSP decodeSP(byte[] encoded) {
		byte nextPayload = encoded[0];
		byte policyNo = encoded[1];
		byte protType = encoded[2];
		byte[] policyParamLenBytes = Arrays.copyOfRange(encoded, 3, 5);
		short policyParamLen = Utils.convertByteArrayToShort(policyParamLenBytes);

		PolicyParam[] policyParams = PolicyParam.decodePolicyParams(
				Arrays.copyOfRange(encoded, 5, 5 + policyParamLen), policyParamLen);

		PayloadSP result = new PayloadSP(nextPayload, policyNo, protType, policyParamLen,
				policyParams);

		result.setEndByte(5 + policyParamLen);
		result.originalBytes = encoded;
		return result;
	}

	/**
	 * Checks if the policyParamLen matches the actual length of the PolicyParam array
	 * @param len
	 * @param params
	 * @return if check passed
	 */
	private boolean checkLengthsOk(short len, PolicyParam[] params) {
		// len is the total length of all the policy parameters.
		int lenCount = 0;

		// Loop through the params, adding to lenCount for every byte
		for (int i = 0; i < params.length; i++) {
			// Add 2 for length and type variables, plus the length of the value
			lenCount += (2 + params[i].getLength());
		}

		return lenCount == len;

	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray();
		bits.appendBits(nextPayload, 8);
		bits.appendBits(policyNo, 8);
		bits.appendBits(protType, 8);
		bits.appendBits(policyParamLen, 16);
		for (int i = 0; i < policyParams.length; i++) {
			bits.appendBitArray(policyParams[i].getEncoded());
		}
		return bits;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("Security Policy Payload.\n");
		str.append("\tNext payload:" + nextPayload + "\n");
		str.append("\tPolicy No: " + policyNo + "\n");
		str.append("\tProt type: " + protType + "\n");
		str.append("\tPolicy param length: " + policyParamLen + "\n");
		str.append("\tPolicy params:\n");
		for (int i = 0; i < policyParams.length; i++) {
			str.append("\t" + policyParams[i].toString());
		}
		return str.toString();
	}

}
