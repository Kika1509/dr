package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import com.google.zxing.common.BitArray;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.mikeysakke.PurposeTag;
import net.kapsch.kms.api.util.KeyUtils;
import net.kapsch.kms.api.util.Utils;

public class KeyUtilsUnitTest {

	private static void checkBitsEquals(byte purposeTag) {

		int keyId = KeyUtils.generateKeyIdentifier(purposeTag);

		BitArray bitArray = Utils.getBitsFromBytes(new byte[] { purposeTag });
		BitArray bitArray2 = Utils.getBitsFromBytes(Utils.intToBytes(keyId));

		// check if the 4 most significant bits are changed
		Assert.assertEquals(bitArray.get(7), bitArray2.get(31));
		Assert.assertEquals(bitArray.get(6), bitArray2.get(30));
		Assert.assertEquals(bitArray.get(5), bitArray2.get(29));
		Assert.assertEquals(bitArray.get(4), bitArray2.get(28));
	}

	@Test
	public void testGenerateUserSalt()
			throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		String mcpttId = "mcptt1@op1.com";
		byte[] gmk = Hex.decode(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

		int userSalt = KeyUtils.generateUserSalt(mcpttId, gmk);

		BitArray bitArray = Utils.getBitsFromBytes(Utils.intToBytes(userSalt));

		// check if the 4 most significant bits of user salt are 0(false)
		Assert.assertTrue(bitArray.isRange(0, 3, false));
	}

	@Test
	public void testGenerateKeyIdentifier() {
		checkBitsEquals(PurposeTag.GMK);
		checkBitsEquals(PurposeTag.PCK);
		checkBitsEquals(PurposeTag.CSK);
		checkBitsEquals(PurposeTag.SPK);
		checkBitsEquals(PurposeTag.MKFC);
		checkBitsEquals(PurposeTag.MSCCK);
	}

}
