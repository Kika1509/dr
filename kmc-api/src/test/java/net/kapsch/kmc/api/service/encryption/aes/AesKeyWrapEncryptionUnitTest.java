package net.kapsch.kmc.api.service.encryption.aes;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.encryption.aes.AesKeyWrapEncryption;
import net.kapsch.kms.api.encryption.aes.AesKeyWrapWithPadding;

public class AesKeyWrapEncryptionUnitTest {

	/**
	 * RFC 3394, Advanced Encryption Standard (AES) Key Wrap Algorithm, 4.3 Wrap 128 bits
	 * of Key Data with a 256-bit KEK
	 */
	@Test
	public void testWrapAndUnwrap() throws NoSuchPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, InvalidAlgorithmParameterException, IOException {

		byte[] kek = Hex.decode(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		SecretKey kekSecretKey = new SecretKeySpec(kek, "AES");

		byte[] keyData = Hex.decode("00112233445566778899AABBCCDDEEFF");
		SecretKey dataSecretKey = new SecretKeySpec(keyData, "AES");

		byte[] wrappedKey = Hex
				.decode("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");

		// wrap
		byte[] wrap = AesKeyWrapEncryption.wrap(dataSecretKey, kekSecretKey);
		// unwrap
		SecretKey unwrap = AesKeyWrapEncryption.unwrap(wrap, kekSecretKey);

		Arrays.equals(wrap, wrappedKey);
		Assert.assertEquals(new String(Hex.encode(wrap)),
				new String(Hex.encode(wrappedKey)));

		Arrays.equals(keyData, unwrap.getEncoded());
		Assert.assertEquals(new String(Hex.encode(keyData)),
				new String(Hex.encode(unwrap.getEncoded())));
	}

	/**
	 * RFC 5649, Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm, 6.
	 * Padded Key Wrap Examples
	 */
	@Test
	public void testWrapAndUnwrapWithPadding() throws InvalidCipherTextException {
		byte[] kek = Hex.decode("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");

		byte[] keyData = Hex.decode("c37b7e6492584340bed12207808941155068f738");
		byte[] wrap = Hex.decode(
				"138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

		byte[] keyData2 = Hex.decode("466f7250617369");
		byte[] wrap2 = Hex.decode("afbeb0f07dfbf5419200f2ccb50bb24f");

		testWrapAndUnwrapWithPaddingCheck(kek, keyData, wrap);
		testWrapAndUnwrapWithPaddingCheck(kek, keyData2, wrap2);
	}

	private void testWrapAndUnwrapWithPaddingCheck(byte[] kek, byte[] keyData,
			byte[] wrap) throws InvalidCipherTextException {
		AesKeyWrapWithPadding aesKeyWrapWithPadding = new AesKeyWrapWithPadding();

		// wrap
		byte[] result = aesKeyWrapWithPadding.wrap(kek, keyData);

		// unwrap
		byte[] unwrap = aesKeyWrapWithPadding.unwrap(kek, result);

		Arrays.equals(result, wrap);
		Assert.assertEquals(new String(Hex.encode(result)), new String(Hex.encode(wrap)));

		Arrays.equals(keyData, unwrap);
		Assert.assertEquals(new String(Hex.encode(keyData)),
				new String(Hex.encode(unwrap)));
	}
}
