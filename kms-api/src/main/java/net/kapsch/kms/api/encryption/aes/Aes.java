package net.kapsch.kms.api.encryption.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class Aes {

	private final static String CIPHER = "AES";

	private static final int AES_KEY_LENGTH_BITS = 128;
	private static final int AES_KEK_LENGTH_BITS = 256;

	private static final String HMAC_ALGORITHM = "HmacSHA256";

	private static final int HMAC_KEY_LENGTH_BITS = 256;

	private Aes() {
	}

	public static SecretKey generateKey(int keyLength) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER);
		// No need to provide a SecureRandom or set a seed since that will
		// happen automatically.
		keyGen.init(keyLength);
		return keyGen.generateKey();
	}

	public static SecretKey getSecretKey(byte[] key)
			throws InvalidKeyException, UnsupportedEncodingException {
		if (key.length != AES_KEY_LENGTH_BITS / Byte.SIZE
				&& key.length != AES_KEK_LENGTH_BITS / Byte.SIZE) {
			throw new InvalidKeyException(
					"Base64 decoded key is not " + AES_KEY_LENGTH_BITS + " bits");
		}

		return new SecretKeySpec(key, CIPHER);
	}

	public static SecretKey getHMACSecretKey(byte[] key)
			throws InvalidKeyException, UnsupportedEncodingException {
		if (key.length != HMAC_KEY_LENGTH_BITS / Byte.SIZE
				&& key.length != AES_KEY_LENGTH_BITS / Byte.SIZE) {
			throw new InvalidKeyException("Base64 decoded key is not "
					+ HMAC_KEY_LENGTH_BITS + " or " + AES_KEY_LENGTH_BITS + " bits");
		}

		return new SecretKeySpec(key, HMAC_ALGORITHM);
	}

	public static byte[] generateMAC(byte[] byteCipherText, SecretKey secretKey)
			throws NoSuchAlgorithmException, InvalidKeyException {
		Mac sha256_HMAC = Mac.getInstance(HMAC_ALGORITHM);
		sha256_HMAC.init(secretKey);

		return sha256_HMAC.doFinal(byteCipherText);
	}

}
