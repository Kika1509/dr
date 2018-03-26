package net.kapsch.kms.api.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import com.google.zxing.common.BitArray;

public final class Utils {

	private Utils() {
	}

	/**
	 * Convert an array of bytes to an array of bits.
	 *
	 * @param bytes - bytes ot be converted
	 * @return the resulting BitArray
	 */
	public static BitArray getBitsFromBytes(final byte[] bytes) {
		BitArray data = new BitArray(0);
		int bytelen = bytes.length;
		for (int i = 0; i < bytelen; i++) {
			data.appendBits(bytes[i], 8);
		}
		return data;
	}

	public static byte[] getBytesFromBits(BitArray bitArray) {
		int size = bitArray.getSizeInBytes();
		byte[] bytes = new byte[size];
		bitArray.toBytes(0, bytes, 0, size);

		return bytes;
	}

	public static byte[] xorBytes(byte[] x, byte[] y) {
		for (int i = 0; i < x.length; i++) {
			x[i] = (byte) (x[i] ^ y[i]);
		}
		return x;
	}

	public static byte[] xorBytesFromLeastSignificant(byte[] x, byte[] y) {
		byte[] result = new byte[y.length];
		int j = y.length - x.length;
		for (int i = 0; i < x.length; i++) {
			while (j < y.length) {
				result[j] = (byte) (x[i] ^ y[j]);
				j++;
				break;
			}
		}
		for (int i = 0; i < x.length; i++) {
			result[i] = y[i];
		}
		return result;
	}

	public static int xor(int x, int y) {
		return x ^ y;
	}

	public static byte[] intToBytes(final int i) {
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(i);
		return bb.array();
	}

	/**
	 * Helper function to convert a byte array consisting of 4 bytes in to an int, or a
	 * byte array consisting of 2 bytes in to an int. This assumes the highest order byte
	 * is first in the byte_number array. In the case of a 2 byte array, the bytes are
	 * considered to represent the two low order bytes of the int.
	 *
	 * @param byte_number - byte to be converted
	 * @return byte_number converted to an int, or 0 if byte_number does not consist of
	 * either two or four bytes.
	 */
	public static int convertByteArrayToInt(final byte[] byte_number) {
		int result = 0;
		if (byte_number.length == 4) {
			result = ((0xFF & byte_number[0]) << 24) | ((0xFF & byte_number[1]) << 16)
					| ((0xFF & byte_number[2]) << 8) | (0xFF & byte_number[3]);
		}
		else if (byte_number.length == 2) {
			result = ((0xFF & byte_number[0]) << 8) | (0xFF & byte_number[1]);
		}

		return result;
	}

	/**
	 * Helper function to convert a byte array consisting of 2 bytes in to a 16 bit short.
	 * This assumes the highest order byte is first in the byte_number array.
	 *
	 * @param byte_number - bytes to be converted
	 * @return byte_number converted to a short, or 0 if byte_number does not consist of
	 * two bytes.
	 */
	public static short convertByteArrayToShort(final byte[] byte_number) {
		short result = 0;

		if (byte_number.length == 2) {
			result = (short) (((0xFF & byte_number[0]) << 8) | (0xFF & byte_number[1]));
		}

		return result;
	}

	/**
	 * Concatenates bytes arrays.
	 *
	 * @param arrays - array of byte arrays to concatenate
	 *
	 * @return concatenated byte arrays
	 *
	 * @throws IOException - throws IOException
	 */
	public static byte[] concatenateByteArrays(byte[]... arrays) throws IOException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		for (byte[] bytes : arrays) {
			outputStream.write(bytes);
		}

		return outputStream.toByteArray();
	}

	/**
	 * Convert short to byte.
	 *
	 * @param x - short number
	 *
	 * @return byte number
	 */
	public static byte[] shortToBytes(short x) {
		byte[] res = new byte[2];
		res[0] = (byte) (x & 0xff);
		res[1] = (byte) ((x >> 8) & 0xff);

		return res;
	}

	/**
	 * Splits an array into n chunks, basic chunk size iz 256 bits
	 *
	 */

	public static byte[][] chunkArray(byte[] array, int n) {
		byte[][] output = new byte[n][];

		for (int i = 0; i < n; ++i) {
			int start = i * 256;
			int length = Math.min(array.length - start, 256);

			byte[] temp = new byte[length];
			System.arraycopy(array, start, temp, 0, length);
			output[i] = temp;
		}

		return output;
	}

	/**
	 * Convert the given long value to an array of 8 bytes (high order byte first).
	 *
	 * @param v the value to convert.
	 * @return an 8 byte array containing a representation of v.
	 */
	public static byte[] longToBytes(long v) {
		byte[] writeBuffer = new byte[8];

		writeBuffer[0] = (byte) (v >>> 56);
		writeBuffer[1] = (byte) (v >>> 48);
		writeBuffer[2] = (byte) (v >>> 40);
		writeBuffer[3] = (byte) (v >>> 32);
		writeBuffer[4] = (byte) (v >>> 24);
		writeBuffer[5] = (byte) (v >>> 16);
		writeBuffer[6] = (byte) (v >>> 8);
		writeBuffer[7] = (byte) (v >>> 0);

		return writeBuffer;
	}
}
