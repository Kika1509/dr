package net.kapsch.kms.api.encryption.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES-128-GCM encryption algorithm, Initialization Vector is randomly selected 96 bit and
 * Additional Authenticated Data(AAD) is not used. See specification 3GPP 33.179 version
 * 13.4.0 (sections References [36], 9.3.4.3 "XML URI attribute encryption").
 */
public final class AesGcmEncryption {

	public static final int GCM_TAG_LENGTH = 16; // in bytes
	private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
	private static final String CHARSET_NAME = "UTF8";

	private static final Logger log = LoggerFactory.getLogger(AesGcmEncryption.class);

	private AesGcmEncryption() {
	}

	private static byte[] encryptDecrypt(byte[] plaintext, SecretKey key, byte[] iv,
			byte[] aad, int mode) throws BadPaddingException, IllegalBlockSizeException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException {
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);

		cipher.init(mode, key, ivSpec);
		if (aad != null) {
			cipher.updateAAD(aad);
			log.debug("AEAD: {}", new String(Hex.encode(aad)));
		}

		byte[] ctAndTag = new byte[cipher.getOutputSize(plaintext.length)];

		int updateSize = cipher.update(plaintext, 0, plaintext.length, ctAndTag, 0);
		cipher.doFinal(new byte[0], 0, 0, ctAndTag, updateSize);

		return ctAndTag;
	}

	public static byte[] encrypt(byte[] data, SecretKey key, byte[] iv, byte[] aad)
			throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			IllegalBlockSizeException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, ShortBufferException {
		log.debug("Encrypting with AEAD...");

		byte[] cypherAndTag = encryptDecrypt(data, key, iv, aad, Cipher.ENCRYPT_MODE);

		log.debug("Cyphertext: {}",
				new String(Hex.encode(Arrays.copyOfRange(cypherAndTag, 0, data.length))));
		log.debug("GMAC: {}", new String(Hex.encode(
				Arrays.copyOfRange(cypherAndTag, data.length, cypherAndTag.length))));

		return cypherAndTag;
	}

	public static String encrypt(String data, SecretKey key, byte[] iv) throws Exception {
		log.debug("Encrypting without AEAD...");

		return Base64.getEncoder()
				.encodeToString(encrypt(data.getBytes(CHARSET_NAME), key, iv, null));
	}

	public static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] iv,
			byte[] aad) throws BadPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, ShortBufferException {
		log.debug("Decrypting with AEAD...");

		byte[] decrypted = encryptDecrypt(encryptedData, key, iv, aad,
				Cipher.DECRYPT_MODE);

		log.debug("Decrpyted: {}", new String(Hex.encode(decrypted)));

		return decrypted;
	}

	public static String decrypt(String encryptedData, SecretKey key, byte[] iv)
			throws Exception {
		log.debug("Decrypting without AEAD...");

		return new String(
				decrypt(Base64.getDecoder().decode(encryptedData), key, iv, null));
	}

}
