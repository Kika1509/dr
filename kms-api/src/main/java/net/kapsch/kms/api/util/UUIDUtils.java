package net.kapsch.kms.api.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public final class UUIDUtils {

	private UUIDUtils() {
	}

	/**
	 * @see #nameUUIDFromBytes(byte[] name)
	 *
	 * @param name A string to be used to construct a {@code UUID}
	 * @return A {@code UUID} generated from the specified array
	 */
	public static UUID nameUUIDFromBytes(String name) {
		return nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Static factory to retrieve a type 5 (name based) {@code UUID} based on the
	 * specified byte array.
	 *
	 * @param name A byte array to be used to construct a {@code UUID}
	 * @return A {@code UUID} generated from the specified array
	 */
	public static UUID nameUUIDFromBytes(byte[] name) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA1");
		}
		catch (NoSuchAlgorithmException nsae) {
			throw new InternalError("SHA1 not supported", nsae);
		}
		byte[] sha1Bytes = md.digest(name);
		sha1Bytes[6] &= 0x0f; /* clear version */
		sha1Bytes[6] |= 0x50; /* set to version 5 */
		sha1Bytes[8] &= 0x3f; /* clear variant */
		sha1Bytes[8] |= 0x80; /* set to IETF variant */
		return fromBytes(sha1Bytes);
	}

	private static UUID fromBytes(byte[] data) {
		// Based on the private UUID(bytes[]) constructor
		long msb = 0;
		long lsb = 0;
		assert data.length >= 16;
		for (int i = 0; i < 8; i++) {
			msb = (msb << 8) | (data[i] & 0xff);
		}
		for (int i = 8; i < 16; i++) {
			lsb = (lsb << 8) | (data[i] & 0xff);
		}
		return new UUID(msb, lsb);
	}
}
