package net.kapsch.kms.api.util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;

import net.kapsch.kms.api.encryption.aes.Aes;

public final class KeyUtils {

	private KeyUtils() {
	}

	/**
	 * The 4 most significant bits of Key Identifier (e.g. GMK-ID, PCK-ID, ...) is the
	 * 'purpose tag' which defines the purpose of the Key Identifier. The 28 least
	 * significant bits of the Key Identifier is a 28-bit randomly-generated value.
	 *
	 * @param purposeTag - The 4 most significant bits of Key Identifier (e.g. GMK-ID,
	 * PCK-ID, ...)
	 *
	 * @return the Key Identifier (e.g. GMK-ID, PCK-ID, ...)
	 */
	public static int generateKeyIdentifier(byte purposeTag) {

		byte[] bytes = new byte[4];
		bytes[3] = purposeTag;

		SecureRandom rn = new SecureRandom();
		int random = rn.nextInt();
		byte[] b = ByteBuffer.allocate(4).putInt(random).array();

		bytes[0] = b[0];
		bytes[1] = b[1];
		bytes[2] = b[2];

		return ByteBuffer.wrap(bytes).getInt();
	}

	/**
	 * For each user, the GMS creates a 28-bit User Salt by hashing the user's MCPTT ID
	 * through a KDF using the GMK as the key as defined in specification 3GPP 33.179
	 * version 13.4.0 (section F.1.3.) Parameters: FC = 0x50, P0 = MCPTT ID, L0 = length
	 * (i.e. 0x00 0x17).
	 *
	 * @param mcpttId - user's MCPTT ID
	 * @param gmk - Group Master Key (GMK)
	 *
	 * @return generated User Salt
	 */
	public static int generateUserSalt(String mcpttId, byte[] gmk)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		String fc = "50";

		// S = FC || P0 || L0 || P1 || L1 || P2 || L2 || P3 || L3 ||... || Pn || Ln
		StringBuilder s = new StringBuilder();
		s.append(fc);
		s.append(mcpttId);
		s.append(EncodingUtils.encodeLengthOf(mcpttId));

		// Derived key = HMAC-SHA-256 ( Key , S )
		SecretKey key = Aes.getHMACSecretKey(gmk);
		byte[] mac = Aes.generateMAC(new String(s).getBytes(), key);

		// The 28 least significant bits of the 256 bits of the KDF output shall be used
		// as the User Salt.
		return Utils.convertByteArrayToInt(Arrays.copyOfRange(mac, 28, 32)) & 0xfffffff;
	}
}
