package net.kapsch.kms.api.encryption.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * RFC 3602, The AES-CBC Cipher Algorithm and Its Use with IPsec.
 */
public final class AesCbcEncryption {

	private static final String CIPHER_TRANSFORMATION = "AES/CBC/NoPadding";

	private AesCbcEncryption() {
	}

	private static byte[] encryptDecrypt(byte[] text, SecretKey secretKey, byte[] iv,
			int mode) throws InvalidAlgorithmParameterException, InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException,
			IllegalBlockSizeException {

		Cipher aesCipherForEncryption = Cipher.getInstance(CIPHER_TRANSFORMATION);
		aesCipherForEncryption.init(mode, secretKey, new IvParameterSpec(iv));

		return aesCipherForEncryption.doFinal(text);
	}

	public static byte[] encrypt(byte[] plaintext, SecretKey secretKey, byte[] iv)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException {

		return AesCbcEncryption.encryptDecrypt(plaintext, secretKey, iv,
				Cipher.ENCRYPT_MODE);
	}

	public static byte[] decrypt(byte[] cipherText, SecretKey secretKey, byte[] iv)
			throws BadPaddingException, IllegalBlockSizeException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException {

		return AesCbcEncryption.encryptDecrypt(cipherText, secretKey, iv,
				Cipher.DECRYPT_MODE);
	}
}
