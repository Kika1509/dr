package net.kapsch.kms.api.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.kapsch.kms.api.ApiConstants;

public final class EncodingUtils {
	private static final Logger log = LoggerFactory.getLogger(EncodingUtils.class);

	private EncodingUtils() {
	}

	public static String encodeInteger(int param, int octetSize) {
		return paddedBinaryString(param, octetSize * 8);
	}

	public static int octetSizeOf(int param) {
		int len = Integer.SIZE - Integer.numberOfLeadingZeros(param);
		int multiple = len / 8;
		int mod = len % 8;
		return mod == 0 ? multiple : ++multiple;
	}

	public static String encodeLengthOf(String param) {
		byte[] bytes = param.getBytes(ApiConstants.DEFAULT_CHARSET);
		return encodeLength(bytes.length);
	}

	public static String encodeLength(int length) {
		return paddedBinaryString(length, 16);
	}

	public static String paddedBinaryString(int param, int len) {
		log.debug("Encoding: {} to length: {}", param, len);
		String paddedBinaryString = Integer.toBinaryString((1 << len) | param)
				.substring(1);
		log.debug("Padded binary string: {}", paddedBinaryString);
		return paddedBinaryString;
	}
}
