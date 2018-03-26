package net.kapsch.kmc.api.service.mikey.utils;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kmc.api.service.SrtpKeys;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;

public class KeyDerivationPrfUnitTest {

	@Test
	public void pTest()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] key = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] data = OctetString.hexStringToByteArray("4869205468657265");
		byte[] wantedResult = OctetString.hexStringToByteArray(
				"198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7");
		byte[] pResult = KeyDerivationPrf.p(key, data, 2);

		Assert.assertEquals(new String(Hex.encode(wantedResult)),
				new String(Hex.encode(pResult)));
		// Arrays.equals(pResult, wantedResult);
	}

	@Test
	public void prfGenerateKeysTest()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] key = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] data = OctetString.hexStringToByteArray("4869205468657265");
		byte[] wantedResult = OctetString.hexStringToByteArray(
				"198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7");
		byte[] prfResult = KeyDerivationPrf.prfGenerateKeys(key, key.length, data, 256);

		Assert.assertEquals(new String(Hex.encode(wantedResult)),
				new String(Hex.encode(prfResult)));
	}

	@Test
	public void derivationMasterAndSaltKeyTest()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] key = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		int csId = 12345;
		int keyId = 56789;
		byte[] rand = OctetString.hexStringToByteArray(
				"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
		SrtpKeys result = KeyDerivationPrf.derivationMasterAndSaltKey(key, rand, keyId,
				csId, keyId);

		SrtpKeys wantedResult = new SrtpKeys(OctetString.hexStringToByteArray(
				"17e4949fc178cb293499c3c6c78e627cc235ce292fe89d9f60b5048a85446362"),
				OctetString.hexStringToByteArray(
						"0da3db1b6cfce48fc850f7fc00f6fbfbeef823e11b29a1301d98497c7f1bf170"),
				keyId);

		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpSalt())),
				new String(Hex.encode(result.getSrtpSalt())));
		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpMaster())),
				new String(Hex.encode(result.getSrtpMaster())));
		Assert.assertEquals(wantedResult.getMki(), result.getMki());
	}
}
