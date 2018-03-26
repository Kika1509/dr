package net.kapsch.kmc.api.service;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.encryption.aes.AesGcmEncryption;
import net.kapsch.kms.api.util.Utils;

/**
 * RFC 3711, Sections: B.2. AES-CM Test Vectors, B.3. Key Derivation Test Vectors
 */
public class KeyStreamGeneratorAesGcmUnitTest {

	@Test
	public void keyDerivationSRTP() throws Exception {
		byte[] expectedSessionKey = Hex.decode("C61E7A93744F39EE10734AFE3FF7A087");
		byte[] expectedSessionSalt = Hex.decode("30CBBC08863D8C85D49DB34A9AE1");

		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] masterSalt = Hex.decode("0EC675AD498AFEEBB6960B3AABE6");

		KeyStreamGeneratorAesGcm keyStreamGenerator = new KeyStreamGeneratorAesGcm(
				masterKey, masterSalt, SrtpProtocol.SRTP);

		Assert.assertTrue(
				Arrays.equals(expectedSessionKey, keyStreamGenerator.getSessionKey()));
		Assert.assertTrue(
				Arrays.equals(expectedSessionSalt, keyStreamGenerator.getSessionSalt()));
	}

	@Test
	public void generationOfKeyStreamSRTP() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] masterSalt = Hex.decode("0EC675AD498AFEEBB6960B3AABE6");
		byte[] ssrc = Hex.decode("00000000");
		String roc = "00000000";
		String seq = "0000";

		// a 32-bit unsigned rollover counter (ROC), which records how many
		// times the 16-bit RTP sequence number has been reset to zero after
		// passing through 65,535. Unlike the sequence number (SEQ), which
		// SRTP extracts from the RTP packet header, the ROC is maintained by
		// SRTP as described in Section 3.3.1. (RFC 3711)

		// We define the index of the SRTP packet corresponding to a given
		// ROC and RTP sequence number to be the 48-bit quantity
		//
		// i = 2^16 * ROC + SEQ.
		byte[] multiRoc = new BigInteger(Hex.decode(roc))
				.multiply(BigInteger.valueOf(2).pow(16)).toByteArray();
		int packetIndex = Integer.parseInt(new String(Hex.encode(multiRoc)))
				+ Integer.parseInt(seq);

		KeyStreamGeneratorAesGcm keyStreamGenerator = new KeyStreamGeneratorAesGcm(
				masterKey, masterSalt, SrtpProtocol.SRTP);

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));
	}

	@Test
	public void keyStreamNotChangeTest() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] masterSalt = Hex.decode("0EC675AD498AFEEBB6960B3AABE6");

		byte[] ivWithCounter = Hex.decode("304e501a4d0341cb2b3bb457db35b7c5");
		byte[] zeroPlaintext = Hex.decode("00000000000000000000000000000000");

		KeyStreamGeneratorAesGcm keyStreamGenerator = new KeyStreamGeneratorAesGcm(
				masterKey, masterSalt, SrtpProtocol.SRTP);
		SecretKey secretKey = Aes.getSecretKey(keyStreamGenerator.getSessionKey());

		byte[] keystream = AesGcmEncryption.encrypt(zeroPlaintext, secretKey,
				ivWithCounter, null);

		byte[] xorKeyStream = Utils.xorBytesFromLeastSignificant(zeroPlaintext,
				keystream);

		byte[] decryptedKeyStream = AesGcmEncryption.decrypt(keystream, secretKey,
				ivWithCounter, null);

		Assert.assertTrue(Arrays.equals(keystream, xorKeyStream));
		Assert.assertTrue(Arrays.equals(zeroPlaintext, decryptedKeyStream));
	}

	@Test
	public void keyStreamChangeTest() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] masterSalt = Hex.decode("0EC675AD498AFEEBB6960B3AABE6");

		byte[] ivWithCounter = Hex.decode("304e501a4d0341cb2b3bb457db35b7c5");
		byte[] nonZeroPlaintext = Hex.decode("abcdabcdabcdabcdabcdabcdabcdabcd");

		KeyStreamGeneratorAesGcm keyStreamGenerator = new KeyStreamGeneratorAesGcm(
				masterKey, masterSalt, SrtpProtocol.SRTP);
		SecretKey secretKey = Aes.getSecretKey(keyStreamGenerator.getSessionKey());

		byte[] keystream = AesGcmEncryption.encrypt(nonZeroPlaintext, secretKey,
				ivWithCounter, null);

		byte[] xorKeyStream = Utils.xorBytesFromLeastSignificant(nonZeroPlaintext,
				keystream);

		byte[] decryptedKeyStream = AesGcmEncryption.decrypt(keystream, secretKey,
				ivWithCounter, null);

		Assert.assertFalse(Arrays.equals(keystream, xorKeyStream));
		Assert.assertTrue(Arrays.equals(nonZeroPlaintext, decryptedKeyStream));
	}

	@Test
	public void srtpAndSrtcpDiffKeysGeneration() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] masterSalt = Hex.decode("0EC675AD498AFEEBB6960B3AABE6");

		KeyStreamGeneratorAesGcm genSrtp = new KeyStreamGeneratorAesGcm(masterKey,
				masterSalt, SrtpProtocol.SRTP);

		KeyStreamGeneratorAesGcm genSrtcp = new KeyStreamGeneratorAesGcm(masterKey,
				masterSalt, SrtpProtocol.SRTCP);

		KeyStreamGeneratorAesGcm genSrtpSecond = new KeyStreamGeneratorAesGcm(masterKey,
				masterSalt, SrtpProtocol.SRTP);

		KeyStreamGeneratorAesGcm genSrtcpSecond = new KeyStreamGeneratorAesGcm(masterKey,
				masterSalt, SrtpProtocol.SRTCP);

		Assert.assertNotEquals(genSrtp.getSessionKey(), genSrtcp.getSessionKey());
		Assert.assertNotEquals(genSrtp.getSessionSalt(), genSrtcp.getSessionSalt());

		Assert.assertTrue(
				Arrays.equals(genSrtp.getSessionKey(), genSrtpSecond.getSessionKey()));
		Assert.assertTrue(
				Arrays.equals(genSrtp.getSessionSalt(), genSrtpSecond.getSessionSalt()));
		Assert.assertTrue(
				Arrays.equals(genSrtcp.getSessionKey(), genSrtcpSecond.getSessionKey()));
		Assert.assertTrue(Arrays.equals(genSrtcp.getSessionSalt(),
				genSrtcpSecond.getSessionSalt()));
	}

	@Test
	public void generationOfKeyStreamSRTCP() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] masterSalt = Hex.decode("0EC675AD498AFEEBB6960B3AABE6");
		byte[] ssrc = Hex.decode("00000000");

		// In the case of SRTCP, the SSRC of the first header of the compound
		// packet MUST be used, i SHALL be the 31-bit SRTCP index and k_e, k_s
		// SHALL be replaced by the SRTCP encryption session key and salt.
		int packetIndex = 5; // todo...

		KeyStreamGeneratorAesGcm keyStreamGenerator = new KeyStreamGeneratorAesGcm(
				masterKey, masterSalt, SrtpProtocol.SRTCP);

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));

		keyStreamGenerator.generateNextKeyStream(ssrc, Utils.intToBytes(packetIndex));
		System.out.println(new String(Hex.encode(keyStreamGenerator.getKeystream())));
	}

}
