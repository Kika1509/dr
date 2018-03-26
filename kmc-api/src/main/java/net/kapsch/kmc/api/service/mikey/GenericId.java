package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.ProtType;
import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

/**
 * Describes a CsIdMapInfo section of the HDR payload, which identifies and maps the
 * crypto sessions to the security protocol sessions for which security associations
 * should be created. See RFC 6043 section 6.1 for more details.
 */
public class GenericId extends CsIdMapInfo {

	/** Default values. */
	public static final byte DEFAULT_CS_ID = 0;
	public static final byte DEFAULT_PROT_TYPE = ProtType.SRTP;
	public static final boolean DEFAULT_S = false;
	public static final byte DEFAULT_P_NUMBER = 1;
	public static final byte DEFAULT_SESSION_DATA_LENGTH = 0;
	public static final byte DEFAULT_SPI_LENGTH = 0;
	/**
	 * CS ID (8 bits): defines the CS ID to be used for the crypto session.
	 */
	private final byte csId;
	/**
	 * Prot type (8 bits): defines the security protocol to be used for the crypto
	 * session. Allowed values are the ones defined for the Prot type field in the SP
	 * payload (see Section 6.10 of [RFC3830]).
	 */
	private final byte protType;
	/**
	 * S (1 bit): flag that MAY be used by the Session Data.
	 */
	private final boolean s;
	/**
	 * #P (7 bits): indicates the number of security policies provided for the crypto
	 * session. In response messages, #P SHALL always be exactly 1. So if #P = 0 in an
	 * initial message, a security profile MUST be provided in the response message. If #P
	 * > 0, one of the suggested policies SHOULD be chosen in the response message. If
	 * needed (e.g., in group communication, see Section 9), the suggested policies MAY be
	 * changed.
	 */
	private final byte pNumber;
	/**
	 * Session Data Length (16 bits): the length of Session Data (in bytes). For the Prot
	 * type SRTP, Session Data MAY be omitted in the initial message (length = 0), but it
	 * MUST be provided in the response message.
	 */
	private final short sessionDataLength;
	/**
	 * SPI Length (8 bits): the length of SPI (in bytes). SPI MAY be omitted in the
	 * initial message (length = 0), but it MUST be provided in the response message.
	 */
	private final short spiLength;
	/**
	 * Ps (variable length): lists the policies for the crypto session. It SHALL contain
	 * exactly #P policies, each having the specified Prot type.
	 */
	private byte[] ps;
	/**
	 * Session Data (variable length): contains session data for the crypto session. The
	 * type of Session Data depends on the specified Prot type.
	 */
	private SessionData[] sessionData;
	/**
	 * SPI (variable length): the SPI (or MKI) corresponding to the session key to
	 * (initially) be used for the crypto session. This does not exclude other keys to be
	 * used. All keys MUST belong to the crypto session bundle.
	 */
	private byte[] spi;

	/**
	 * Default constructor for creating a Generic ID for use in a PayloadHDR. Many
	 * variables are not required in this usage.
	 */
	public GenericId() {
		this.csId = DEFAULT_CS_ID;
		protType = DEFAULT_PROT_TYPE;
		s = DEFAULT_S;
		pNumber = DEFAULT_P_NUMBER;
		ps = new byte[] { 1 };
		sessionDataLength = DEFAULT_SESSION_DATA_LENGTH;
		sessionData = new SessionData[0];
		spiLength = DEFAULT_SPI_LENGTH;
	}

	public GenericId(final byte cs_id, final byte prot_type, // NOSONAR
			final boolean _s, final int p_number, byte[] p_s,
			final int session_data_length, final SessionData[] session_data,
			final int spi_length, final byte[] spi_data) {
		if ((p_number > 0 && p_number != p_s.length)
				|| (spi_length > 0 && spi_length != spi_data.length)) {
			throw new IllegalArgumentException(
					"Given length does not match actual length");
		}
		csId = cs_id;
		protType = prot_type;
		s = _s;
		pNumber = (byte) p_number;
		ps = p_s;
		sessionDataLength = (short) session_data_length;
		sessionData = session_data;
		spiLength = (short) spi_length;
		spi = spi_data;
	}

	public GenericId(final byte cs_id, final byte prot_type, final boolean _s, byte[] p_s,
			final SessionData[] session_data, final byte[] spi_data) {
		this(cs_id, prot_type, _s, p_s.length, p_s, session_data.length, session_data,
				spi_data.length, spi_data);
	}

	public GenericId(final byte cs_id, final byte prot_type, final boolean _s, // NOSONAR
			final int p_number, byte[] p_s, final int session_data_length,
			final byte[] session_data, final int spi_length, final byte[] spi_data) {
		this(cs_id, prot_type, _s, p_s.length, p_s, session_data.length, SessionData
				.decodeSessionData(_s, session_data, (short) session_data.length),
				spi_data.length, spi_data);
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

	private static int hashCode(Object[] array) {
		int prime = 31;
		if (array == null) {
			return 0;
		}
		int result = 1;
		for (int index = 0; index < array.length; index++) {
			result = prime * result
					+ (array[index] == null ? 0 : array[index].hashCode());
		}
		return result;
	}

	/**
	 * Decodes the given byte array into a CsIdMapInfo object.
	 * @param encoded_map_info - used as a return of the remaining bytes
	 * @return CsIdMapInfo
	 */
	public static GenericId decodeCsIdMapInfo(byte[] encoded_map_info) {
		GenericId result = null;

		if (encoded_map_info != null && encoded_map_info.length >= 6) {
			int index = 0;
			// CS ID is the first byte...
			byte cs_id = encoded_map_info[index];
			// Protocol type is the second byte...
			index++;
			byte prot_type = encoded_map_info[index];
			// S and P are the next byte, 1 bit is S and 7 bits are P...
			index++;
			byte s_and_p = encoded_map_info[index];
			int s_bit_int = (s_and_p) >> 7; // shift 7 to get first bit
			boolean s_bit = s_bit_int == 0 ? false : true;

			int p_bits = (s_and_p & 0x7f); // bitmask 127 to get rid of first
											// bit

			// get policies
			index++;
			byte[] policies;
			policies = getPolicies(p_bits, index, encoded_map_info);
			if (policies != null) {
				index += p_bits;
			}

			// get session data length
			byte[] session_data_length = new byte[2];
			session_data_length[0] = encoded_map_info[index];
			index++;
			session_data_length[1] = encoded_map_info[index];
			index++;

			int session_data_len = Utils.convertByteArrayToInt(session_data_length);

			// get the actual session data (if the session data length is 0 this
			// will not do anything)
			byte[] session_data;
			session_data = getActualSessionData(session_data_len, index,
					encoded_map_info);
			if (session_data != null) {
				index += session_data_len;
			}

			SessionData[] sessionData = SessionData.decodeSessionData(s_bit, session_data,
					(short) session_data_len);

			int spi_length = encoded_map_info[index];
			index++;

			byte[] spi_data;
			spi_data = getSpiData(spi_length, index, encoded_map_info);
			if (spi_data != null) {
				index += spi_length;
			}

			result = new GenericId(cs_id, prot_type, s_bit, p_bits, policies,
					session_data_len, sessionData, spi_length, spi_data);
			result.setEndByte(index);
			result.originalBytes = encoded_map_info;
		}

		return result;
	}

	private static byte[] getSpiData(int spi_length, int index, byte[] encoded_map_info) {
		byte[] spi_data = null;
		if (spi_length > 0) {
			spi_data = new byte[spi_length];
			for (int i = index; i < index + spi_length; i++) {
				spi_data[i - index] = encoded_map_info[i];
			}
		}
		return spi_data;
	}

	private static byte[] getActualSessionData(int session_data_len, int index,
			byte[] encoded_map_info) {
		byte[] session_data = null;
		if (session_data_len > 0) {
			session_data = new byte[session_data_len];

			// byte[] other_session_data = new byte[session_data_len]; //NOSONAR
			for (int i = 0; i < session_data_len; i++) {
				session_data[i] = encoded_map_info[index + i];
			}
		}
		return session_data;
	}

	private static byte[] getPolicies(int p_bits, int index, byte[] encoded_map_info) {
		byte[] policies = null;
		if (p_bits > 0) {
			policies = new byte[p_bits];
			for (int i = 0; i < p_bits; i++) {
				policies[i] = encoded_map_info[index + i];
			}
		}
		return policies;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray();
		bits.appendBits(csId, 8);
		bits.appendBits(protType, 8);
		int s_flag = s ? 1 : 0;
		bits.appendBits(s_flag, 1);
		bits.appendBits(pNumber, 7);
		if (pNumber > 0 && ps != null) {
			for (int i = 0; i < ps.length; i++) {
				bits.appendBits(ps[i], 8);
			}
		}
		bits.appendBits(sessionDataLength, 16);
		if (sessionDataLength > 0 && sessionData != null && sessionData.length > 0) {
			for (int i = 0; i < sessionData.length; i++) {
				bits.appendBitArray(sessionData[i].getEncoded());
			}
		}

		bits.appendBits(spiLength, 8);
		if (spiLength > 0 && spi != null && spi.length > 0) {
			for (int i = 0; i < spi.length; i++) {
				bits.appendBits(spi[i], 8);
			}
		}

		return bits;
	}

	public int getSizeInBytes() {
		int size = 6 + spi.length;
		if (s) {
			size += (sessionData.length * 10);
		}
		else {
			size += (sessionData.length * 4);
		}
		return size;
	}

	public byte getCsId() {
		return csId;
	}

	public byte getProtType() {
		return protType;
	}

	public boolean isS() {
		return s;
	}

	public byte getPNumber() {
		return pNumber;
	}

	public byte[] getPs() {
		return ps;
	}

	public short getSessionDataLength() {
		return sessionDataLength;
	}

	public SessionData[] getSessionData() {
		return sessionData;
	}

	public short getSpiLength() {
		return spiLength;
	}

	public byte[] getSpi() {
		return spi;
	}

	@Override
	public int hashCode() {
		final int PRIME = 31;
		int result = super.hashCode();
		result = PRIME * result + csId;
		result = PRIME * result + pNumber;
		result = PRIME * result + protType;
		result = PRIME * result + GenericId.hashCode(ps);
		result = PRIME * result + (s ? 1231 : 1237);
		result = PRIME * result + GenericId.hashCode(sessionData);
		result = PRIME * result + sessionDataLength;
		result = PRIME * result + GenericId.hashCode(spi);
		result = PRIME * result + spiLength;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj != null && getClass() != obj.getClass()) {
			return false;
		}
		GenericId other = (GenericId) obj;
		if (other != null) {
			if (csId != other.csId || pNumber != other.pNumber
					|| protType != other.protType || !Arrays.areEqual(ps, other.ps)
					|| s != other.s || sessionData.length != other.getSessionData().length
					|| sessionDataLength != other.sessionDataLength
					|| !Arrays.areEqual(spi, other.spi) || spiLength != other.spiLength) {
				return false;
			}
			for (int i = 0; i < sessionData.length; i++) {
				if (sessionData[i] != other.getSessionData()[i]) {
					return false;
				}
			}
		}
		return true;
	}

	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("Generic-ID CS ID Map Info.\n");
		str.append("\tCS ID: " + csId + "\n");
		str.append("\tProt type: " + protType + "\n");
		str.append("\tS: " + s + "\n");
		str.append("\t#P: " + pNumber + "\n");
		for (int i = 0; i < ps.length; i++) {
			str.append("\t\t" + ps[i] + "\n");
		}
		str.append("\tSession Data Length: " + sessionDataLength + "\n");
		str.append("\tSession Data:");
		for (int i = 0; i < sessionData.length; i++) {
			str.append(" " + sessionData[i]);
		}
		str.append("\n");
		str.append("\tSPI Length: " + spiLength + "\n");
		str.append("\tSPI:");
		for (int i = 0; i < spi.length; i++) {
			str.append(" " + spi[i]);
		}
		str.append("\n");
		return str.toString();
	}
}
