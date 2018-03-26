package net.kapsch.kmc.api.service.encryption.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.encryption.aes.AesGcmEncryption;

/**
 * RFC 7714, 16.1.1. SRTP AEAD_AES_128_GCM Encryption, 16.1.2. SRTP AEAD_AES_128_GCM
 * Decryption
 */
public class AesGcmEncryptionUnitTest {

	@Test
	public void encryptAndDecryptTest() throws UnsupportedEncodingException,
			InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException,
			NoSuchAlgorithmException, BadPaddingException,
			InvalidAlgorithmParameterException, ShortBufferException {
		byte[] packet = Hex.decode(
				"47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573");
		byte[] iv = Hex.decode("51753c6580c2726f20718414");
		byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
		byte[] aad = Hex.decode("8040f17b8041f8d35501a0b2");

		byte[] encryptedPacket = Hex.decode(
				"f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833");

		byte[] encryptedAndTaggedPacket = Hex.decode(
				"f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce");

		SecretKey secretKey = Aes.getSecretKey(key);

		System.out.println("\nDATA:\n");
		System.out.println(new String(packet));
		System.out.println(new String(Hex.encode(packet)));
		System.out.println();

		byte[] resultCipherWithTag = AesGcmEncryption.encrypt(packet, secretKey, iv, aad);
		System.out.println("\nDATA AFTER ENCRYPTION:\n");
		System.out.println(new String(resultCipherWithTag));
		System.out.println(new String(Hex.encode(resultCipherWithTag)));
		System.out.println();

		Assert.assertTrue(Arrays.equals(encryptedAndTaggedPacket, resultCipherWithTag));
		Assert.assertTrue(Arrays.equals(encryptedPacket,
				Arrays.copyOfRange(encryptedAndTaggedPacket, 0, packet.length)));

		byte[] decryptedAndVerifiedPacket = AesGcmEncryption.decrypt(resultCipherWithTag,
				secretKey, iv, aad);
		System.out.println("\nDATA AFTER DECRYPTION:\n");
		System.out.println(new String(decryptedAndVerifiedPacket));
		System.out.println(new String(Hex.encode(decryptedAndVerifiedPacket)));
		System.out.println();

		Assert.assertTrue(Arrays.equals(packet, decryptedAndVerifiedPacket));
	}

	@Test
	public void encryptAndDecryptWithoutAADTest() throws Exception {
		String data = "somebody@mcptt.org";
		byte[] key = Hex.decode("06a9214036b8a15b512e03d534120006");
		SecretKey secretKey = Aes.getSecretKey(key);

		byte[] iv = new byte[96 / 8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);

		String encrypted = AesGcmEncryption.encrypt(data, secretKey, iv);

		String decrypted = AesGcmEncryption.decrypt(encrypted, secretKey, iv);

		Assert.assertEquals(data, decrypted);
	}
}
