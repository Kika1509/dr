package net.kapsch.kms.api.encryption.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class AesCmEncryption {

	private AesCmEncryption() {
	}

	public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

		return cipher.doFinal(data);
	}

	public static byte[] decrypt(byte[] key, byte[] msg) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);

		return cipher.doFinal(msg);
	}
}
