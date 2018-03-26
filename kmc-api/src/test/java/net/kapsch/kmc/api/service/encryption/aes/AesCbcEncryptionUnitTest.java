package net.kapsch.kmc.api.service.encryption.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.encryption.aes.AesCbcEncryption;

/**
 * Tests for AesCbcEncryption class. See RFC 3602, The AES-CBC Cipher Algorithm and Its
 * Use with IPsec (Section 4. Test Vectors, first 4 test cases)
 */
public class AesCbcEncryptionUnitTest {

	private void testEncryptAnddecrypt(byte[] key, byte[] plainText, byte[] iv,
			String expectedCipher)
			throws UnsupportedEncodingException, InvalidKeyException,
			IllegalBlockSizeException, InvalidAlgorithmParameterException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		// generate key
		SecretKey secretKey = Aes.getSecretKey(key);

		// encrypt
		System.out.println("\nDATA:\n");
		System.out.println(new String(plainText));
		byte[] cipherText = AesCbcEncryption.encrypt(plainText, secretKey, iv);
		Assert.assertEquals(expectedCipher, new String(Hex.encode(cipherText)));

		System.out.println("\nAFTER ENCRYPTION:\n");
		System.out.println(new String(cipherText));

		// descrypt
		byte[] decipherText = AesCbcEncryption.decrypt(cipherText, secretKey, iv);
		Assert.assertEquals(new String(plainText), new String(decipherText));

		System.out.println("\nAFTER DECRYPTION:\n");
		System.out.println(new String(decipherText));
	}

	// Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key
	@Test
	public void EncryptingOneBlockBytes() throws InvalidKeyException,
			IllegalBlockSizeException, InvalidAlgorithmParameterException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException {

		byte[] key = Hex.decode("06a9214036b8a15b512e03d534120006");
		String plainText = "Single block msg";
		byte[] iv = Hex.decode("3dafba429d9eb430b422da802c9fac41");
		String expectedCipher = "e353779c1079aeb82708942dbe77181a";

		testEncryptAnddecrypt(key, plainText.getBytes(), iv, expectedCipher);
	}

	// Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key
	@Test
	public void EncryptingTwoBlockBytes() throws InvalidKeyException,
			IllegalBlockSizeException, InvalidAlgorithmParameterException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException {

		byte[] key = Hex.decode("c286696d887c9aa0611bbb3e2025a45a");
		byte[] plainText = Hex.decode(
				"000102030405060708090a0b0c0d0e0f" + "101112131415161718191a1b1c1d1e1f");
		byte[] iv = Hex.decode("562e17996d093d28ddb3ba695a2e6f58");
		String expectedCipher = "d296cd94c2cccf8a3a863028b5e1dc0a"
				+ "7586602d253cfff91b8266bea6d61ab1";

		testEncryptAnddecrypt(key, plainText, iv, expectedCipher);
	}

	// Case #3: Encrypting 48 bytes (3 blocks) using AES-CBC with 128-bit key
	@Test
	public void EncryptingThreeBlockBytes() throws InvalidKeyException,
			IllegalBlockSizeException, InvalidAlgorithmParameterException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException {

		byte[] key = Hex.decode("6c3ea0477630ce21a2ce334aa746c2cd");
		String plainText = "This is a 48-byte message (exactly 3 AES blocks)";
		byte[] iv = Hex.decode("c782dc4c098c66cbd9cd27d825682c81");
		String expectedCipher = "d0a02b3836451753d493665d33f0e886"
				+ "2dea54cdb293abc7506939276772f8d5" + "021c19216bad525c8579695d83ba2684";

		testEncryptAnddecrypt(key, plainText.getBytes(), iv, expectedCipher);
	}

	// Case #4: Encrypting 64 bytes (4 blocks) using AES-CBC with 128-bit key
	@Test
	public void EncryptingFourBlockBytes() throws InvalidKeyException,
			IllegalBlockSizeException, InvalidAlgorithmParameterException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException {

		byte[] key = Hex.decode("56e47a38c5598974bc46903dba290349");
		byte[] plainText = Hex.decode("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
				+ "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
				+ "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
		byte[] iv = Hex.decode("8ce82eefbea0da3c44699ed7db51b7d9");
		String expectedCipher = "c30e32ffedc0774e6aff6af0869f71aa"
				+ "0f3af07a9a31a9c684db207eb0ef8e4e" + "35907aa632c3ffdf868bb7b29d3d46ad"
				+ "83ce9f9a102ee99d49a53e87f4c3da55";

		testEncryptAnddecrypt(key, plainText, iv, expectedCipher);
	}

}
