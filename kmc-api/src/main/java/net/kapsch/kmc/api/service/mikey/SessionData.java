package net.kapsch.kmc.api.service.mikey;

import java.util.ArrayList;

import com.google.zxing.common.BitArray;

import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Represents a Session Data part of the CS ID map info for the GENERIC-ID map type. RFC
 * 6043 section 6.1.1
 *
 */
public class SessionData {

	int ssrc;
	int roc; // optional
	short seq; // optional
	boolean includeOptional;

	public SessionData(int ssrc) {
		includeOptional = false;
		this.ssrc = ssrc;
	}

	public SessionData(int ssrc, int roc, short seq) {
		includeOptional = true;
		this.ssrc = ssrc;
		this.roc = seq;
	}

	public static SessionData[] decodeSessionData(boolean s, byte[] encoded,
			short totalLen) {
		int ssrc;
		int roc;
		short seq;

		ArrayList data = new ArrayList();
		for (int i = 0; i < totalLen; i++) {
			SessionData sessionData;
			byte[] ssrcBytes = Arrays.copyOfRange(encoded, i, i + 4);

			ssrc = Utils.convertByteArrayToInt(ssrcBytes);
			if (s) {
				byte[] rocBytes = Arrays.copyOfRange(encoded, i + 4, i + 8);
				byte[] seqBytes = Arrays.copyOfRange(encoded, i + 8, i + 10);
				roc = Utils.convertByteArrayToInt(rocBytes);
				seq = Utils.convertByteArrayToShort(seqBytes);
				i += 6; // NOSONAR
				sessionData = new SessionData(ssrc, roc, seq);
			}
			else {
				sessionData = new SessionData(ssrc);
			}
			data.add(sessionData);
			i += 3; // i increases after every loop, so only ads 3 here //NOSONAR
		}

		SessionData[] result = new SessionData[data.size()];
		for (int i = 0; i < result.length; i++) {
			result[i] = (SessionData) data.get(i);
		}

		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray();
		bits.appendBits(ssrc, 32);
		if (includeOptional) {
			bits.appendBits(roc, 32);
			bits.appendBits(seq, 16);
		}

		return bits;
	}

	@Override
	public int hashCode() {
		int result = this.ssrc;
		result = 31 * result + this.roc;
		result = 31 * result + (int) this.seq;
		result = 31 * result + (this.includeOptional ? 1 : 0);
		return result;
	}

	@Override
	public boolean equals(Object o) {
		SessionData other = (SessionData) o;
		if (other != null) {
			return ssrc == other.getSsrc() && roc == other.getRoc()
					&& seq == other.getSeq();
		}
		else {
			throw new NullPointerException("other can't be null");
		}
	}

	public int getSsrc() {
		return ssrc;
	}

	public int getRoc() {
		return roc;
	}

	public short getSeq() {
		return seq;
	}

	public boolean includeOptional() {
		return includeOptional;
	}
}
