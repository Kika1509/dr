package net.kapsch.kmc.api.service.mikey.utils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.util.Utils;

/**
 * These shall be used to generate the SRTP Master Key and SRTP Master Salt as specified
 * in IETF RFC 3830 [22]. The key derivation function defined in section 4.1. 3 of RFC
 * 3830 [22] using the PRF-HMAC-SHA-256 Pseudo-Random Function as described in IETF RFC
 * 6043 [25], section 6.1 shall be supported for generating the SRTP Master Key and Salt.
 */
public final class KeyDerivationPrf {

	private static final String TEK_CONSTANT = "0x2AD01C64";
	private static final String SALTING_KEY_CONSTANT = "0x39A2C14B";

	/**
	 * The values "256" and "160" equals half the input block-size and full output hash
	 * size, respectively, of the SHA-1 hash as part of the P- function.
	 */
	private static final int HALF_INPUT_BLOCK_SIZE = 256;
	private static final int FULL_OUTPUT_HASH_SIZE = 160;

	private KeyDerivationPrf() {
	}


	public static byte[] prfGenerateKeys(byte[] tgk, int tgkLen, byte[] label,
			int outKeyLen)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		int n = (int) Math.ceil((double) tgkLen / HALF_INPUT_BLOCK_SIZE);
		byte[][] splitedKey = Utils.chunkArray(tgk, n);
		int m = (int) Math.ceil((double) outKeyLen / FULL_OUTPUT_HASH_SIZE);
		byte[] result = p(splitedKey[0], label, m);
		for (int s = 1; s < n; s++) {
			result = Utils.xorBytes(result, p(splitedKey[s], label, m));
		}
		return result;
	}

	public static byte[] p(byte[] key, byte[] label, int m)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		byte[][] a = new byte[m][];
		byte[] result = new byte[0];

		SecretKey s = Aes.getHMACSecretKey(key);
		a[0] = label;
		a[1] = Aes.generateMAC(a[0], s);
		result = Utils.concatenateByteArrays(result, a[1]);
		for (int i = 2; i < m; i++) {
			a[i] = Aes.generateMAC(a[i - 1], s);
			result = Utils.concatenateByteArrays(result, a[i]);
		}
		return result;
	}
}
