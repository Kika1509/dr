package net.kapsch.kms.api.encryption.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public final class AesKeyWrapEncryption {

	public static final String CIPHER = "AES";
	private static final String CIPHER_TRANSFORMATION = "AESWrap";

	private AesKeyWrapEncryption() {
	}

	public static byte[] wrap(SecretKey secretKey, Key kek)
			throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, NoSuchProviderException {

		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.WRAP_MODE, kek);

		return cipher.wrap(secretKey);
	}

	public static SecretKey unwrap(byte[] wrappedKey, Key kek)
			throws BadPaddingException, IllegalBlockSizeException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {

		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.UNWRAP_MODE, kek);

		return (SecretKey) cipher.unwrap(wrappedKey, CIPHER, Cipher.SECRET_KEY);
	}
}
