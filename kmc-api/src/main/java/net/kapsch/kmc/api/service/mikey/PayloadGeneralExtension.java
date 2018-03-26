package net.kapsch.kmc.api.service.mikey;

import java.security.SecureRandom;
import java.util.Arrays;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.GeneralExtensionType;
import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kms.api.util.Utils;

/**
 * The concatenated 'MCPTT group ID', 'Activation time', 'Text', 'Reserved' and 'Random
 * padding' elements shall be encrypted using AES-128 in Cipher Block Chaining mode using
 * the IV (16 octets) as Initial Vector, as described in IETF RFC 3602 [23]. The
 * encryption key shall be the GMK.
 */
public class PayloadGeneralExtension extends Payload {

	public static final byte DEFAULT_NEXT_PAYLOAD = NextPayload.SIGN;
	public static final byte DEFAULT_TYPE = GeneralExtensionType.VENDOR_ID;
	public static final int DEFAULT_IV_SIZE = 16;

	/**
	 * The IV shall be randomly chosen by the GMS, and shall be 16 octets in length.
	 */
	private final byte[] iv;

	/**
	 * Type (8 bits): identifies the type of general payload.
	 */
	private final byte type;

	/**
	 * Length (16 bits): the length in bytes of the Data field.
	 */
	private short length;

	/**
	 * Data field.
	 */
	private byte[] data;

	/**
	 * Need to set data with setData() method.
	 */
	public PayloadGeneralExtension() {
		this.payloadType = NextPayload.GENERAL_EXT;
		this.nextPayload = DEFAULT_NEXT_PAYLOAD;
		this.iv = generateIV();
		this.type = DEFAULT_TYPE;
		this.length = 0;
	}

	public PayloadGeneralExtension(byte[] data) {
		this.payloadType = NextPayload.GENERAL_EXT;
		this.nextPayload = DEFAULT_NEXT_PAYLOAD;
		this.iv = generateIV();
		this.type = DEFAULT_TYPE;
		this.data = data;
		this.length = (short) data.length;
	}

	public PayloadGeneralExtension(byte nextPayload, byte[] iv, byte type, short length,
			byte[] data) {
		this.payloadType = NextPayload.GENERAL_EXT;
		this.nextPayload = nextPayload;
		this.iv = iv;
		this.type = type;
		this.length = length;
		this.data = data;
	}

	public static PayloadGeneralExtension decode(final byte[] encoded) {
		byte nextPayload = encoded[0];
		byte[] iv = Arrays.copyOfRange(encoded, 1, DEFAULT_IV_SIZE + 1);
		byte type = encoded[DEFAULT_IV_SIZE + 1];
		byte[] dataLenArray = { encoded[DEFAULT_IV_SIZE + 2],
				encoded[DEFAULT_IV_SIZE + 3] };
		short length = Utils.convertByteArrayToShort(dataLenArray);
		byte[] data = Arrays.copyOfRange(encoded, DEFAULT_IV_SIZE + 4,
				DEFAULT_IV_SIZE + 4 + length);

		return new PayloadGeneralExtension(nextPayload, iv, type, length, data);
	}

	public static int getDefaultIvSize() {
		return DEFAULT_IV_SIZE;
	}

	@Override
	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);
		bits.appendBits(this.nextPayload, 8);
		bits.appendBitArray(Utils.getBitsFromBytes(this.iv));
		bits.appendBits(this.type, 8);
		bits.appendBits(this.length, 16);
		bits.appendBitArray(Utils.getBitsFromBytes(this.data));

		return bits;
	}

	private byte[] generateIV() {
		SecureRandom random = new SecureRandom();
		byte[] randBytes = new byte[DEFAULT_IV_SIZE];
		random.nextBytes(randBytes);

		return randBytes;
	}

	public byte[] getIv() {
		return this.iv;
	}

	public byte getType() {
		return this.type;
	}

	public short getLength() {
		return this.length;
	}

	public byte[] getData() {
		return this.data;
	}

	public void setData(byte[] data) {
		this.data = data;
		this.length = (short) data.length;
	}

	@Override
	public String toString() {
		return "PayloadGeneralExtension{" + "iv=" + Arrays.toString(iv) + ", type=" + type
				+ ", length=" + length + ", data=" + Arrays.toString(data) + '}';
	}
}
