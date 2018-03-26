package net.kapsch.kms.api.util;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

/**
 * Test {@link MikeySakkeUid} which provides the functionality of generating Mikey-Sakke
 * UID
 *
 * Asserts 256 bit length
 */
public class MikeySakkeUidTest {
	@Test
	public void generateUidUnitTest() {

		String uidHex = MikeySakkeUid.generateUid("user@example.org",
				"kms.example.org", 2592000, 0,
				1514);

		Assert.assertNotNull(uidHex);

		String bitString = new BigInteger(uidHex, 16).toString(2);

		Assert.assertTrue(bitString.length() == 256);
	}

	@Test
	public void generate() {
		String uidHex = MikeySakkeUid.generateUid("user@example.org",
				"kms.example.org", 2592000, 0,
				1514);

		String uidHex2 = MikeySakkeUid.generateUid("user@example.org",
				"kms.example.org", 2592000, 0,
				1514);

		String uidHex3 = MikeySakkeUid.generateUid("user2@example.org",
				"kms3.example.org", 2592000, 0,
				1514);

		System.out.println(uidHex);
		System.out.println(uidHex2);
		System.out.println(uidHex3);
	}
}
