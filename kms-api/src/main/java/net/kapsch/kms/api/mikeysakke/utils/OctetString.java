package net.kapsch.kms.api.mikeysakke.utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;

import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;

/**
 * Utility classed used to contain and manipulate keys and data for use in MIKEY SAKKE
 * encryptions scheme. Data is stored in an underlying byte array.
 */
public class OctetString {
	/**
	 * The byte array used as the data storage.
	 */
	private byte[] octets;

	/**
	 * Create an empty octet string.
	 */
	public OctetString() {
		this.octets = new byte[0];
	}

	/**
	 * Create an empty octet string of length n.
	 *
	 * @param n The length of the empty octet string in bytes
	 */
	public OctetString(final int n) {
		this.octets = new byte[n];
	}

	/**
	 * Create an octet string with the given byte array.
	 *
	 * @param bytes The byte array to use as the octet string
	 */
	public OctetString(final byte[] bytes) {
		setOctets(bytes);
	}

	/**
	 * Creates an octet string representing an big integer.
	 *
	 * @param bigint The big integer to store in the octet string
	 *
	 * @param length The size of the octet string to store the big integer in
	 */
	public OctetString(final BigInteger bigint, final int length) {
		byte[] bytes = bigint.toByteArray();
		int diff = bytes.length - length;

		if (diff < 0) {
			this.octets = new byte[-diff];
			this.append(bytes);
		}
		else if (diff > 0) {
			if (bytes[0] == 0 && diff == 1) {
				this.octets = new byte[bytes.length - 1];
				System.arraycopy(bytes, 1, this.octets, 0, this.octets.length);
			}
			else {
				throw new IllegalArgumentException(
						"BigInteger too large to fit into length");
			}
		}
		else {
			setOctets(bytes);
		}

	}

	/**
	 * Creates an octet string representing an elliptical curve point.
	 *
	 * @param point The elliptical curve point to store in an octet string
	 */
	public OctetString(final ECPoint point) {
		byte[] encoded = point.getEncoded();
		setOctets(encoded);
	}

	/**
	 * Creates an octet string based on another octet string. The octet string produced
	 * will be a deep copy.
	 *
	 * @param octetStringToCopy The octet string to copy from
	 */
	public OctetString(final OctetString octetStringToCopy) {
		// If the octet string is empty or not the same length as the octets to
		// copy define a new byte array
		byte[] octetsToCopy = octetStringToCopy.octets;
		if (empty() || this.octets.length != octetsToCopy.length) {
			this.octets = new byte[octetsToCopy.length];
		}

		// Copy the bytes
		System.arraycopy(octetsToCopy, 0, this.octets, 0, octetsToCopy.length);
	}

	/**
	 * Create an octet string from a hexadecimal string.
	 *
	 * @param hexString The hex string representing the data to store in the octet string
	 * @return The octet string that represents the hex data.
	 */
	public static OctetString fromHex(final String hexString) {
		OctetString result = new OctetString();
		byte[] hexBytes = hexStringToByteArray(hexString);
		result.setOctets(hexBytes);
		return result;
	}

	/**
	 * Create an octet string from an string with ascii characters.
	 *
	 * @param asciiString The string to convert and store in an octet string
	 * @return The octet string representing the ascii string
	 */
	public static OctetString fromAscii(final String asciiString) {
		OctetString result = new OctetString();
		try {
			byte[] asciiBytes = asciiString.getBytes("ISO-8859-1");
			result.setOctets(asciiBytes);
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException(
					"Invalid ASCII string : Unsupported encoding");
		}
		return result;
	}

	/**
	 * Converts a hex string to a byte array.
	 *
	 * @param hexString The hex string to convert
	 * @return The corresponding byte array.
	 */
	public static byte[] hexStringToByteArray(final String hexString) {
		// Check if the hex string is in multiples of two, and
		// if not, zero pad it
		String hexToConvert = hexString;
		int hexStringLength = hexString.length();
		if (hexStringLength % 2 == 1) {
			hexToConvert = "0" + hexToConvert;
			hexStringLength++;
		}

		// In multiples of two, convert each hex pair to the corresponding byte
		final int HEX_BASE16 = 16;
		final int BIT_SHIFT_MULTIPLY_BY_4 = 4;
		byte[] data = new byte[hexStringLength / 2];
		for (int i = 0; i < hexStringLength; i += 2) {
			// Convert the characters seperately and then combine them to create
			// the correct byte.
			int firstChar = Character.digit(hexToConvert.charAt(i), HEX_BASE16);
			int secondChar = Character.digit(hexToConvert.charAt(i + 1), HEX_BASE16);
			data[i / 2] = (byte) ((firstChar << BIT_SHIFT_MULTIPLY_BY_4) + secondChar);
		}
		return data;
	}

	/**
	 * Returns the hexadecimal representation of the octet string.
	 *
	 * @return The octet string in hex
	 */
	public static String toHexString(byte[] octets) {
		StringBuilder hex = new StringBuilder();

		final int BIT_MASK_FIRST_HEX_CHAR = 0xF0;
		final int BIT_MASK_SECOND_HEX_CHAR = 0x0F;
		final int NIBBLE_BIT_SHIFT = 4;

		// Loop through each byte and append the first and second hex values.
		for (byte octet : octets) {
			hex.append(Integer
					.toHexString((octet & BIT_MASK_FIRST_HEX_CHAR) >> NIBBLE_BIT_SHIFT));
			hex.append(Integer.toHexString(octet & BIT_MASK_SECOND_HEX_CHAR));
		}
		return hex.toString();
	}

	/**
	 * Create a octet string from a substring of the provided octet string.
	 *
	 * @param startIndex The starting byte index to copy from
	 * @param length The number of bytes to copy
	 * @return An octet string containing the substring
	 */
	public OctetString subString(final int startIndex, final int length) {
		int totalLength = this.octets.length;
		// Check if the starting index and length represent valid substring
		// inside the octet string.
		if (length + startIndex > totalLength) {
			throw new IllegalArgumentException(
					"Specified substring lies outside the range of the octet string");
		}

		// Create a new octet string and copy the corresponding bytes.
		OctetString result = new OctetString(length);
		System.arraycopy(this.octets, startIndex, result.octets, 0, length);
		return result;
	}

	/**
	 * Create an octet string from a substring of the provided octet string. Copy from the
	 * starting index to the end of the octet string.
	 *
	 * @param startIndex The starting byte index to copy from
	 * @return An octet string containing the bytes from the starting index to the end
	 * provided string.
	 */
	public OctetString subString(final int startIndex) {
		return this.subString(startIndex, size() - startIndex);
	}

	/**
	 * Returns the ASCII representation of the octet string.
	 *
	 * @return The octet string in ASCII characters
	 */
	public String toAscii() {
		try {
			return new String(this.octets, "ISO-8859-1");
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException(
					"Unable to convert to ASCII : Unsupported encoding");
		}
	}

	public String toHex() {
		return toHexString(this.octets);
	}

	/**
	 * Default representation of octet string in hex.
	 *
	 * @return The octet string in hex
	 */
	public String toString() {
		return toHexString(this.octets);
	}

	/**
	 * Set the octets of an octet string based on a provided octet string. Note that the
	 * produced octet string will share the same byte array as the provided octet string.
	 *
	 * @param octetString The octet string to reference
	 */
	public void setOctets(final OctetString octetString) {
		setOctets(octetString.getOctets());
	}

	/**
	 * Get the underlying byte array of an octet string.
	 *
	 * @return The byte array representing the octet string
	 */
	public byte[] getOctets() {
		return this.octets;
	}

	/**
	 * Set the octets of an octet string based on the provided byte array. The produced
	 * octet string will reference the provided byte array.
	 *
	 * @param octets The byte array to use in the octet string
	 */
	private void setOctets(final byte[] octets) {
		this.octets = octets;
	}

	/**
	 * Determines if the octet string is empty.
	 *
	 * @return True if the octet string is empty
	 */
	public boolean empty() {
		return (this.octets == null || this.octets.length == 0);
	}

	/**
	 * Determines if the octet string contains all zeroes
	 *
	 * @return true if octet string contains all zeroes
	 */
	public boolean allZeroes() {
		for (int i = 0; i < size(); i++) {
			if (this.octets[i] != 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Appends the given octet string to this octet string.
	 *
	 * @param stringToAppend The octet string to append to this octet string
	 */
	public void append(final OctetString stringToAppend) {
		append(stringToAppend.getOctets());
	}

	/**
	 * Appends a byte array to the octet string.
	 *
	 * @param bytes The byte array containing the bytes to append to the string
	 */
	private void append(final byte[] bytes) {
		// Create a new byte array to hold the final octet string
		byte[] newOctets = new byte[this.octets.length + bytes.length];

		// Loop through each byte assigning the correct byte.
		for (int i = 0; i < newOctets.length; i++) {
			newOctets[i] = i < this.octets.length ? this.octets[i]
					: bytes[i - this.octets.length];
		}
		setOctets(newOctets);
	}

	/**
	 * Appends a null terminator to the end of the octet string.
	 */
	public void appendNullTerminator() {
		append(new byte[1]);
	}

	/**
	 * Returns the size of the octet string in bytes.
	 *
	 * @return The size of the octet string in bytes
	 */
	public int size() {
		return this.octets.length;
	}

	/**
	 * Determines if one octet string is equal to another.
	 *
	 * @param o The octet string to check against
	 * @return True if the octets hold the same values in their byte arrays
	 */

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof OctetString)) {
			return false;
		}

		OctetString that = (OctetString) o;

		// First check size
		if (size() != that.size()) {
			return false;
		}

		// Secondly, check each byte, if any of them are different, return false
		for (int i = 0; i < size(); i++) {
			if (this.octets[i] != that.octets[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Determines the hash code for the octet string. Is simply the hashcode for the byte
	 * array.
	 *
	 * @return The hash code
	 */
	public int hashCode() {
		return Arrays.hashCode(this.octets);
	}
}
