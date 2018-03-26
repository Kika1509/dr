package net.kapsch.kmc.api.service.mikey;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Arrays;

import com.google.zxing.common.BitArray;

import net.kapsch.kmc.api.service.mikey.tables.GeneralExtensionStatus;
import net.kapsch.kms.api.util.Utils;

public class PayloadGeneralExtensionData {

	public static final byte DEFAULT_STATUS = GeneralExtensionStatus.NOT_REVOKED;
	private static final int ACTIVATION_TIME_BYTE_SIZE = 8;

	/**
	 * The 'MCPTT group ID' element.
	 */
	private final McpttGroupId mcpttGroupId;

	/**
	 * The 'Activation time' element shall define the time in UTC at which the associated
	 * GMK is to be made active for transmission. It shall be 8 octets in length.
	 */
	private final byte[] activationTime;

	/**
	 * The 'Text' element.
	 */
	private final Text text;
	/**
	 * The five elements specified in the preceding five subclauses shall be padded by
	 * 0-15 octets of random data such that the total length of the 'General extension
	 * payload' shall be a multiple of 32 octets, to satisfy the block size requirements
	 * of the payload protection algorithm.
	 */
	private final byte[] randomPadding;
	/**
	 * The 'Status' element shall determine the current status of the GMK. It shall be 4
	 * octets in length.
	 */
	private final int status;
	/**
	 * The 'Reserved' element.
	 */
	private Reserved reserved;

	public PayloadGeneralExtensionData(byte[] mcpttGroupId, byte[] activationTime,
			byte[] text) throws Exception {
		this.mcpttGroupId = new McpttGroupId(mcpttGroupId);
		if (activationTime.length != ACTIVATION_TIME_BYTE_SIZE) {
			throw new Exception("Activation time should be 8 octets in length.");
		}
		this.activationTime = activationTime;
		this.text = new Text(text);
		this.reserved = new Reserved(new byte[0]);
		this.status = DEFAULT_STATUS;
		int length = this.mcpttGroupId.getEncoded().getSizeInBytes()
				+ this.activationTime.length + this.text.getEncoded().getSizeInBytes()
				+ this.reserved.getEncoded().getSizeInBytes() + Byte.SIZE / 8;
		this.randomPadding = generateRandomPadding(32, length);
	}

	public PayloadGeneralExtensionData(McpttGroupId mcpttGroupId, byte[] activationTime,
			Text text, Reserved reserved, byte[] randomPadding, int status)
			throws Exception {
		if (activationTime.length != ACTIVATION_TIME_BYTE_SIZE) {
			throw new Exception("Activation time should be 8 octets in length.");
		}
		this.mcpttGroupId = mcpttGroupId;
		this.activationTime = activationTime;
		this.text = text;
		this.reserved = reserved;
		this.randomPadding = randomPadding;
		this.status = status;
	}

	public static PayloadGeneralExtensionData decode(final byte[] encoded)
			throws Exception {
		int start = 0;

		// decode mcpttGroupId
		McpttGroupId mcpttGroupId = McpttGroupId
				.decode(Arrays.copyOfRange(encoded, start, encoded.length));
		start += mcpttGroupId.length + Short.SIZE / 8 + mcpttGroupId.randomPadding.length;

		// decode activationTime
		byte[] activationTime = Arrays.copyOfRange(encoded, start, start + 8);
		start += 8;

		// decode text
		Text text = Text.decode(Arrays.copyOfRange(encoded, start, encoded.length));
		start += text.length + Short.SIZE / 8 + text.randomPadding.length;

		// decode reserved
		Reserved reserved = Reserved
				.decode(Arrays.copyOfRange(encoded, start, encoded.length));
		start += reserved.length + Short.SIZE / 8 + reserved.randomPadding.length;

		// decode status
		byte status = encoded[start];
		start += Byte.SIZE / 8;

		// decode randomPadding
		int lenFive = mcpttGroupId.getEncoded().getSizeInBytes() + activationTime.length
				+ text.getEncoded().getSizeInBytes()
				+ reserved.getEncoded().getSizeInBytes() + Byte.SIZE / 8;
		int randomPaddingSize = generateRandomPadding(32, lenFive).length;
		byte[] randomPadding = Arrays.copyOfRange(encoded, start,
				start + randomPaddingSize);

		return new PayloadGeneralExtensionData(mcpttGroupId, activationTime, text,
				reserved, randomPadding, status);
	}

	private static byte[] generateRandomPadding(int multiple, int length) {
		if (length == Short.SIZE / 8) {
			return new byte[0];
		}
		else {
			int paddingLenght = getPaddingLenght(multiple, length);

			SecureRandom random = new SecureRandom();
			byte[] randBytes = new byte[paddingLenght];
			random.nextBytes(randBytes);

			return randBytes;
		}
	}

	private static int getPaddingLenght(int multiple, int length) {
		if (length == Short.SIZE / 8) {
			return 0;
		}
		else {
			return multiple - (length % multiple);
		}
	}

	public static byte getDefaultStatus() {
		return DEFAULT_STATUS;
	}

	public BitArray getEncoded() {
		BitArray bits = new BitArray(0);
		bits.appendBitArray(this.mcpttGroupId.getEncoded());
		bits.appendBitArray(Utils.getBitsFromBytes(this.activationTime));
		bits.appendBitArray(this.text.getEncoded());
		bits.appendBitArray(this.reserved.getEncoded());
		bits.appendBits(this.status, Byte.SIZE);
		bits.appendBitArray(Utils.getBitsFromBytes(this.randomPadding));

		return bits;
	}

	public BitArray getMcpttGroupId() {
		return this.mcpttGroupId.getEncoded();
	}

	public byte[] getActivationTime() {
		return this.activationTime;
	}

	public BitArray getText() {
		return this.text.getEncoded();
	}

	public byte[] getRandomPadding() {
		return this.randomPadding;
	}

	public int getStatus() {
		return this.status;
	}

	public BitArray getReserved() {
		return this.reserved.getEncoded();
	}

	/**
	 * The 'MCPTT group ID' element shall consist of two sub-elements followed by 0-3
	 * bytes of random padding. A two octet 'Length' sub-element shall followed by an
	 * 'MCPTT group ID' sub-element, where this sub-element shall be encoded as ASCII 8
	 * bit text. The 'Length' element shall indicate the length in octets of the 'MCPTT
	 * group ID' subelement only, and the count of the length shall not include the
	 * 'Length' sub-element itself, and shall not include the length of any following
	 * random padding. Following the 'MCPTT group ID' sub-element, 0 -3 octets of random
	 * padding shall be added so that the total length of the ('Length' sub-element +
	 * 'MCPTT group ID' sub-element + random padding) shall be a multiple of 4 octets.
	 */
	private static final class McpttGroupId {

		private final short length;
		private final byte[] mcpttGroupId;
		private final byte[] randomPadding;

		private McpttGroupId(byte[] mcpttGroupId) {
			this.mcpttGroupId = mcpttGroupId;
			this.length = (short) mcpttGroupId.length;
			this.randomPadding = generateRandomPadding(4, Short.SIZE / 8 + this.length);
		}

		private McpttGroupId(short length, byte[] mcpttGroupId, byte[] randomPadding) {
			this.length = length;
			this.mcpttGroupId = mcpttGroupId;
			this.randomPadding = randomPadding;
		}

		private static McpttGroupId decode(final byte[] encoded) {
			byte[] dataLenArray = { encoded[0], encoded[1] };
			short length = Utils.convertByteArrayToShort(dataLenArray);
			byte[] mcpttId = Arrays.copyOfRange(encoded, Short.SIZE / 8,
					Short.SIZE / 8 + length);
			byte[] randomPadding = Arrays.copyOfRange(encoded, Short.SIZE / 8 + length,
					Short.SIZE / 8 + length
							+ getPaddingLenght(4, Short.SIZE / 8 + length));

			return new McpttGroupId(length, mcpttId, randomPadding);
		}

		private BitArray getEncoded() {
			BitArray bits = new BitArray(0);
			bits.appendBits(this.length, Short.SIZE);
			bits.appendBitArray(Utils.getBitsFromBytes(this.mcpttGroupId));
			bits.appendBitArray(Utils.getBitsFromBytes(this.randomPadding));

			return bits;
		}

		@Override
		public String toString() {
			return "McpttGroupId{" + "length=" + length + ", mcpttGroupId="
					+ Arrays.toString(mcpttGroupId) + ", randomPadding="
					+ Arrays.toString(randomPadding) + '}';
		}
	}

	/**
	 * The 'Text' element shall consist of two sub-elements followed by 0-3 bytes of
	 * random padding. A two octet 'Length' sub-element shall followed by a 'Text'
	 * sub-element, where this sub-element shall be encoded as ASCII 8 bit text. The
	 * 'Length' element shall indicate the length in octets of the 'Text' sub-element
	 * only, and the count of the length shall not include the 'Length' sub-element
	 * itself, and shall not include the length of any following random padding. Following
	 * the 'Text' sub-element, 0 -3 octets of random padding shall be added so that the
	 * total length of the ('Length' sub-element + 'Text' sub-element + random padding)
	 * shall be a multiple of 4 octets.
	 */
	private static final class Text {

		private final short length;
		private final byte[] text;
		private final byte[] randomPadding;

		private Text(byte[] text) throws UnsupportedEncodingException {
			this.text = (text != null) ? text : new byte[0];
			this.length = (text != null) ? (short) text.length : 0;
			this.randomPadding = generateRandomPadding(4, Short.SIZE / 8 + this.length);
		}

		private Text(short length, byte[] text, byte[] randomPadding) {
			this.length = length;
			this.text = text;
			this.randomPadding = randomPadding;
		}

		private static Text decode(final byte[] encoded)
				throws UnsupportedEncodingException {
			byte[] dataLenArray = { encoded[0], encoded[1] };
			short length = Utils.convertByteArrayToShort(dataLenArray);
			byte[] text = Arrays.copyOfRange(encoded, Short.SIZE / 8,
					Short.SIZE / 8 + length);
			byte[] randomPadding = Arrays.copyOfRange(encoded, Short.SIZE / 8 + length,
					Short.SIZE / 8 + length
							+ getPaddingLenght(4, Short.SIZE / 8 + length));

			return new Text(length, text, randomPadding);
		}

		private BitArray getEncoded() {
			BitArray bits = new BitArray(0);
			bits.appendBits(this.length, Short.SIZE);
			bits.appendBitArray(Utils.getBitsFromBytes(this.text));
			bits.appendBitArray(Utils.getBitsFromBytes(this.randomPadding));

			return bits;
		}

		@Override
		public String toString() {
			return "Text{" + "length=" + length + ", text=" + Arrays.toString(text)
					+ ", randomPadding=" + Arrays.toString(randomPadding) + '}';
		}
	}

	/**
	 * The 'Reserved' element shall consist of two sub-elements. A two octet 'Length'
	 * sub-element shall be followed by a 'Reserved' sub-element, where the definition and
	 * encoding of this sub-element is outside the scope of the present document, and
	 * shall be ignored by the receiving client. The 'Length' element shall indicate the
	 * length in octets of the 'Text' sub-element only, and the count of the length shall
	 * not include the 'Length' sub-element itself. The length of the sum of the ('Length'
	 * sub-element + 'Reserved' sub-element) shall be a multiple of 4 octets.
	 */
	private static final class Reserved {

		private final short length;
		private final byte[] reserved;
		private final byte[] randomPadding;

		private Reserved(byte[] reserved) {
			this.reserved = reserved;
			this.length = (short) reserved.length;
			this.randomPadding = generateRandomPadding(4, Short.SIZE / 8 + this.length);
		}

		private Reserved(short length, byte[] reserved, byte[] randomPadding) {
			this.length = length;
			this.reserved = reserved;
			this.randomPadding = randomPadding;
		}

		private static Reserved decode(final byte[] encoded) {
			byte[] dataLenArray = { encoded[0], encoded[1] };
			short length = Utils.convertByteArrayToShort(dataLenArray);
			byte[] reserved = Arrays.copyOfRange(encoded, Short.SIZE / 8,
					Short.SIZE / 8 + length);
			byte[] randomPadding = Arrays.copyOfRange(encoded, Short.SIZE / 8 + length,
					Short.SIZE / 8 + length
							+ getPaddingLenght(4, Short.SIZE / 8 + length));

			return new Reserved(length, reserved, randomPadding);
		}

		private BitArray getEncoded() {
			BitArray bits = new BitArray(0);
			bits.appendBits(this.length, Short.SIZE);
			bits.appendBitArray(Utils.getBitsFromBytes(this.reserved));
			bits.appendBitArray(Utils.getBitsFromBytes(this.randomPadding));

			return bits;
		}

		@Override
		public String toString() {
			return "Reserved{" + "length=" + length + ", reserved="
					+ Arrays.toString(reserved) + ", randomPadding="
					+ Arrays.toString(randomPadding) + '}';
		}
	}
}
