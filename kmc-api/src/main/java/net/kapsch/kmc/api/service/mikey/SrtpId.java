package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a CsIdMapInfo section of the HDR payload, which identifies and maps the
 * crypto sessions to the security protocol sessions for which security associations
 * should be created. See RFC 3830 section 6.1.1 for more details.
 */
public class SrtpId extends CsIdMapInfo {

	byte[] policyNo;
	int[] ssrc;
	int[] roc;

	public SrtpId() {
		this(new byte[0], new int[0], new int[0]);
	}

	public SrtpId(byte policy1, int ssrc1, int roc1) {
		this(new byte[] { policy1 }, new int[] { ssrc1 }, new int[] { roc1 });
	}

	public SrtpId(byte[] policies, int[] ssrcs, int[] rocs) {
		this.policyNo = Arrays.copyOf(policies, policies.length);
		this.ssrc = Arrays.copyOf(ssrcs, ssrcs.length);
		this.roc = Arrays.copyOf(rocs, rocs.length);
	}

	/**
	 * Decodes the given byte array into an SrtpId
	 * @param encoded - encoded data
	 * @param csNo - the number of CryptoSessions
	 * @return the decoded SrtpId.
	 */
	public static SrtpId decode(byte[] encoded, byte csNo) {
		byte[] policies = new byte[csNo];
		int[] ssrcs = new int[csNo];
		int[] rocs = new int[csNo];

		int endbyte = 0;
		for (int i = 0; i < csNo; i++) {
			byte policy = encoded[i];
			byte[] ssrcbytes = Arrays.copyOfRange(encoded, i + 1, i + 5);
			int ssrc = Utils.convertByteArrayToInt(ssrcbytes);
			byte[] rocbytes = Arrays.copyOfRange(encoded, i + 5, i + 9);
			int roc = Utils.convertByteArrayToInt(rocbytes);
			endbyte = endbyte + 9;
			policies[i] = policy;
			ssrcs[i] = ssrc;
			rocs[i] = roc;
		}

		SrtpId result = new SrtpId(policies, ssrcs, rocs);
		result.setEndByte(endbyte);
		result.originalBytes = encoded;
		return result;

	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray();
		for (int i = 0; i < policyNo.length; i++) {
			bits.appendBits(policyNo[i], 8);
			bits.appendBits(ssrc[i], 32);
			bits.appendBits(roc[i], 32);
		}
		return bits;
	}

	public void addPolicy(byte policyNo, int ssrc, int roc) {
		int newPolicyLen = this.policyNo.length + 1;
		byte[] newPolicies = new byte[newPolicyLen];
		int[] newSsrcs = new int[newPolicyLen];
		int[] newRocs = new int[newPolicyLen];

		for (int i = 0; i < newPolicyLen - 1; i++) {
			newPolicies[i] = this.policyNo[i];
			newSsrcs[i] = this.ssrc[i];
			newRocs[i] = this.roc[i];
		}

		newPolicies[newPolicyLen - 1] = policyNo;
		newSsrcs[newPolicyLen - 1] = ssrc;
		newRocs[newPolicyLen - 1] = roc;

		this.policyNo = Arrays.copyOf(newPolicies, newPolicyLen);
		this.ssrc = Arrays.copyOf(newSsrcs, newPolicyLen);
		this.roc = Arrays.copyOf(newRocs, newPolicyLen);
	}

	public int[] getSSRCs() {
		return ssrc;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("SRTP-ID CS ID Map Info.\n");
		for (int i = 0; i < policyNo.length; i++) {
			str.append("\tPolicyNo: " + policyNo[i]);
			str.append("\tSSRC: " + ssrc[i]);
			str.append("\tROC: " + roc[i]);
			str.append("\n");
		}
		return str.toString();
	}

}
