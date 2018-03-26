package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.CsIdMapType;
import net.kapsch.kmc.api.service.mikey.tables.DataType;
import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kmc.api.service.mikey.tables.PRFFunc;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a Common Header Payload for a MIKEY-SAKKE I_MESSAGE. See RFC 6509 section
 * 4.1, RFC 6043 section 6.1, and RFC 3830 section 6.1 for more details.
 *
 * The Common Header payload MUST always be present as the first payload in each message.
 * The Common Header includes a general description of the exchange message.
 */
public class PayloadHDR extends Payload {

	/* Default values */
	public static final byte DEFAULT_VERSION = 1;
	public static final byte DEFAULT_DATA_TYPE = DataType.SAKKE;
	public static final byte HDR_DEFAULT_NEXT_PAYLOAD = NextPayload.T;
	public static final boolean DEFAULT_V = false; // 0
	public static final byte DEFAULT_PRF_FUNC = PRFFunc.PRF_HMAC_SHA_256;
	public static final byte DEFAULT_CS_NUMBER = 0;
	public static final byte DEFAULT_CS_ID_MAP_TYPE = CsIdMapType.GENERIC_ID;

	/**
	 * version (8 bits): the version number of MIKEY (which is 1).
	 */
	private final byte version;

	/**
	 * data type (8 bits): describes the type of message (SAKKE message is 26).
	 */
	private final byte dataType;

	/**
	 * RFC6509 4.1 V (1 bit): flag to indicate whether a response message is expected
	 * ('1') or not ('0'). It MUST be set to '0' and ignored by the Responder in a SAKKE
	 * message.
	 */
	private final boolean v;

	/**
	 * PRF func (7 bits): indicates the PRF function that has been/will be used for key
	 * derivation.
	 */
	private final byte prfFunc;

	/**
	 * CSB ID (32 bits): identifies the CSB. It is RECOMMENDED that the CSB ID be chosen
	 * at random by the Initiator. This ID MUST be unique between each Initiator-Responder
	 * pair, i.e., not globally unique. An Initiator MUST check for collisions when
	 * choosing the ID (if the Initiator already has one or more established CSBs with the
	 * Responder). The Responder uses the same CSB ID in the response.
	 */
	private final int csbId;

	/**
	 * #CS (8 bits): indicates the number of Crypto Sessions that will be handled within
	 * the CBS. Note that even though it is possible to use 255 CSs, it is not likely that
	 * a CSB will include this many CSs. The integer 0 is interpreted as no CS included.
	 * This may be the case in an initial setup message.
	 */
	private final byte csNumber;

	/**
	 * CS ID map type (8 bits): specifies the method of uniquely mapping Crypto Sessions
	 * to the security protocol sessions.
	 */
	private final byte csIdMapType;

	/**
	 * CS ID map info (variable length): identifies and maps the crypto sessions to the
	 * security protocol sessions for which security associations should be created.
	 */
	private final CsIdMapInfo csIdMapInfo;

	public PayloadHDR(final byte version, final byte dataType, final byte nextPayload, // NOSONAR
			final boolean v, final byte prfFunc, final int csbId, final byte csNumber,
			final byte csIdMapType, final CsIdMapInfo csIdMapInfo) {
		if (version != 1) {
			throw new IllegalArgumentException("Only MIKEY version 1 supported");
		}

		this.version = version;
		this.dataType = dataType;
		this.nextPayload = nextPayload;
		this.v = v;
		this.prfFunc = prfFunc;
		this.csbId = csbId;
		this.csNumber = csNumber;
		this.csIdMapType = csIdMapType;
		this.csIdMapInfo = csIdMapInfo;
	}

	public PayloadHDR(final int csbId, final CsIdMapInfo csIdMapInfo) {
		version = DEFAULT_VERSION;
		dataType = DEFAULT_DATA_TYPE;
		nextPayload = HDR_DEFAULT_NEXT_PAYLOAD;
		v = DEFAULT_V;
		prfFunc = DEFAULT_PRF_FUNC;
		this.csbId = csbId;
		csNumber = DEFAULT_CS_NUMBER;
		csIdMapType = DEFAULT_CS_ID_MAP_TYPE;
		this.csIdMapInfo = csIdMapInfo;

	}

	/**
	 * Decode the given byte array into a PayloadHDR object.
	 *
	 * @param encoded_hdr - will be returned with the used bytes removed
	 * @return - decoded PayloadHDR object
	 * @throws MikeyException - throws MikeyException exception
	 */
	public static PayloadHDR decodeHDR(final byte[] encoded_hdr) throws MikeyException {
		PayloadHDR result = null;

		if (encoded_hdr != null && encoded_hdr.length >= 16) {
			// Version is the first byte...
			byte version = encoded_hdr[0];
			// Data type is the second byte...
			byte data_type = encoded_hdr[1];
			// Next payload is the third byte...
			byte next_payload = encoded_hdr[2];
			// V and PRF Func are the fourth byte, 1 bit is V and 7 bits are PRF
			// Func...
			byte v_and_prf = encoded_hdr[3];
			int v_bit_int = (v_and_prf) >> 7;
			boolean v_bit = v_bit_int == 0 ? false : true;
			byte prf_bits = (byte) (v_and_prf & 0x7f); // bitmask 127 to get rid
														// of first bit

			// CSB ID is the fifth-eighth bytes
			byte[] csb_id_bytes = new byte[4];
			for (int i = 0; i < csb_id_bytes.length; i++) {
				csb_id_bytes[i] = encoded_hdr[i + 4];
			}
			int csb_id = Utils.convertByteArrayToInt(csb_id_bytes);

			// CS# us the ninth byte
			byte cs_number = encoded_hdr[8];
			// CS ID map type is the tenth byte
			byte cs_id_map_type = encoded_hdr[9];

			byte[] remaining_bytes = Arrays.copyOfRange(encoded_hdr, 10,
					encoded_hdr.length);

			// next is CS ID Map Info:
			CsIdMapInfo info = null;

			switch (cs_id_map_type) {
			case CsIdMapType.GENERIC_ID:
				info = GenericId.decodeCsIdMapInfo(remaining_bytes);
				break;
			case CsIdMapType.SRTP_ID:
				info = SrtpId.decode(remaining_bytes, cs_number);
				break;
			default:
				throw new MikeyException("Given CS ID Map Type not yet supported.");
			}

			result = new PayloadHDR(version, data_type, next_payload, v_bit, prf_bits,
					csb_id, cs_number, cs_id_map_type, info);
			result.originalBytes = encoded_hdr;
			result.startByte = 0;
			result.setEndByte(10 + info.getEndByte());
		}

		return result;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);
		bits.appendBits(version, 8);
		bits.appendBits(dataType, 8);
		bits.appendBits(nextPayload, 8);
		bits.appendBit(v);
		bits.appendBits(prfFunc, 7);
		bits.appendBits(csbId, 32);
		bits.appendBits(csNumber, 8);
		bits.appendBits(csIdMapType, 8);
		bits.appendBitArray(csIdMapInfo.getEncoded());

		return bits;
	}

	public byte getVersion() {
		return version;
	}

	public byte getDataType() {
		return dataType;
	}

	public boolean isV() {
		return v;
	}

	public byte getPrfFunc() {
		return prfFunc;
	}

	public int getCsbId() {
		return csbId;
	}

	public byte getCsNumber() {
		return csNumber;
	}

	public byte getCsIdMapType() {
		return csIdMapType;
	}

	public CsIdMapInfo getCsIdMapInfo() {
		return csIdMapInfo;
	}

	@Override
	public int hashCode() {
		final int PRIME = 31;
		int result = 1;
		result = PRIME * result + ((csIdMapInfo == null) ? 0 : csIdMapInfo.hashCode());
		result = PRIME * result + csIdMapType;
		result = PRIME * result + csNumber;
		result = PRIME * result + csbId;
		result = PRIME * result + dataType;
		result = PRIME * result + prfFunc;
		result = PRIME * result + (v ? 1231 : 1237);
		result = PRIME * result + version;
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
		PayloadHDR other = (PayloadHDR) obj;
		if (csIdMapInfo == null) {
			if (other.csIdMapInfo != null) {
				return false;
			}
		}
		else if (!csIdMapInfo.equals(other.csIdMapInfo)) {
			return false;
		}
		if (csIdMapType != other.csIdMapType) {
			return false;
		}
		if (csNumber != other.csNumber) {
			return false;
		}
		if (csbId != other.csbId) {
			return false;
		}
		if (dataType != other.dataType) {
			return false;
		}
		if (prfFunc != other.prfFunc) {
			return false;
		}
		if (v != other.v) {
			return false;
		}
		if (version != other.version) {
			return false;
		}
		return true;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("Common Header Payload.\n");
		str.append("\tVersion: " + version + "\n");
		str.append("\tData type: " + dataType + "\n");
		str.append("\tNext payload: " + nextPayload + "\n");
		str.append("\tV: " + v + "\n");
		str.append("\tPRF func: " + prfFunc + "\n");
		str.append("\tCSB ID: " + csbId + "\n");
		str.append("\t#CS: " + csNumber + "\n");
		str.append("\t" + csIdMapInfo.toString());

		return str.toString();
	}
}
