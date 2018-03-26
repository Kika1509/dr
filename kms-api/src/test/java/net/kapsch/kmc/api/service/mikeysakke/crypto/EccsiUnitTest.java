package net.kapsch.kmc.api.service.mikeysakke.crypto;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import net.kapsch.kms.api.mikeysakke.crypto.Eccsi;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.util.MikeySakkeUid;

public class EccsiUnitTest {

	private final static String MCPTT_ID = "test4@example.org";

	private final static String KMS_URI = "kms.example.org";

	private final static int KEY_PERIOD_LENGHT = 2419200;

	private final static int KEY_PERIOD_OFFSET = 0;

	private final static int CURRENT_KEY_PERIOD_NO = 1540;

	private final static OctetString PVT_KMS = OctetString.fromHex(
			"0486CE73931E8CC9F7BE69AA0FBF209E6337AE81FB54C7902E196E149F88CCE12FABBEA9EC55B428857B723EE6886B723688FFE53C310E1BF360BA245F7537F5BC");

	private final static OctetString KPAK_KMS = OctetString.fromHex(
			"04F868905AA9ECC443F294154B686BDC05518562B991066E83997D69E7B4A1EE1E40BAA8CCDEF68B0D09107EDAC5B364002F5BD4E2AD01DEFC76BB3D49F735C46E");

	private final static OctetString SSK_KMS = OctetString
			.fromHex("FFBDC8277AFC84EB0C56B788CF2FDD5090B5F694F051B89A723911C95E456D0C");

	// RFC test data, https://tools.ietf.org/html/rfc6507
	private final static OctetString IDENTIFIER_RFC = OctetString
			.fromAscii("2011-02\0tel:+447700900123\0");

	private final static OctetString PVT_RFC = OctetString.fromHex("04"
			+ "758A142779BE89E829E71984CB40EF75" + "8CC4AD775FC5B9A3E1C8ED52F6FA36D9"
			+ "A79D247692F4EDA3A6BDAB77D6AA6474" + "A464AE4934663C5265BA7018BA091F79");

	private final static OctetString KPAK_RFC = OctetString.fromHex("04"
			+ "50D4670BDE75244F28D2838A0D25558A" + "7A72686D4522D4C8273FB6442AEBFA93"
			+ "DBDD37551AFD263B5DFD617F3960C65A" + "8C298850FF99F20366DCE7D4367217F4");

	private final static OctetString SSK_RFC = OctetString
			.fromHex("23F374AE1F4033F3E9DBDDAAEF20F4CF0B86BBD5A138A5AE9E7E006B34489A0D");

	private final static OctetString SIGN_MESSAGE = OctetString.fromAscii("message\0"); // hex:
																						// 6D657373
																						// 61676500

	private static final OctetString SIGNATURE = OctetString.fromHex(
			"269D4C8FDEB66A74E4EF8C0D5DCC597D" + "DFE6029C2AFFC4936008CD2CC1045D81"
					+ "E09B528D0EF8D6DF1AA3ECBF80110CFC"
					+ "EC9FC68252CEBB679F4134846940CCFD" + "04"
					+ "758A142779BE89E829E71984CB40EF75"
					+ "8CC4AD775FC5B9A3E1C8ED52F6FA36D9"
					+ "A79D247692F4EDA3A6BDAB77D6AA6474"
					+ "A464AE4934663C5265BA7018BA091F79");

	private static final String EMPTY_HASH_MESSAGE = "Implementation currently requires cached HS";

	private OctetString hash;

	@Before
	public void setup() {
		this.hash = new OctetString();

		Assert.assertEquals("", this.hash.toString());
	}

	@Test
	public void testValidateSigningKeysOK() throws Exception {
		OctetString id = createIdentifier();

		boolean validate = Eccsi.validateSigningKeys(id, PVT_KMS, KPAK_KMS, SSK_KMS,
				this.hash);

		Assert.assertTrue(validate);
		Assert.assertNotEquals("", this.hash.toString());
	}

	@Test
	public void testValidateSigningKeysOkRfcParams() throws Exception {
		boolean validate = Eccsi.validateSigningKeys(IDENTIFIER_RFC, PVT_RFC, KPAK_RFC,
				SSK_RFC, this.hash);

		Assert.assertTrue(validate);
		Assert.assertNotEquals("", this.hash.toString());
	}

	@Test
	public void testValidateSigningKeysBadIdentifier() throws Exception {
		// month changed 02 -> 01
		OctetString badIdentifier = OctetString.fromAscii("2011-01\0tel:+447700900123\0");
		OctetString hash = new OctetString();

		Assert.assertEquals("", hash.toString());

		// validate with wrong identifier, validation should return false
		boolean validate = Eccsi.validateSigningKeys(badIdentifier, PVT_RFC, KPAK_RFC,
				SSK_RFC, hash);

		Assert.assertFalse(validate);
		Assert.assertNotEquals("", hash.toString());
	}

	@Test
	public void testValidateSigningKeysBadPvt() throws Exception {
		// last charachter changed 9 -> 8
		OctetString badPvt = OctetString.fromHex("04" + "758A142779BE89E829E71984CB40EF75"
				+ "8CC4AD775FC5B9A3E1C8ED52F6FA36D9" + "A79D247692F4EDA3A6BDAB77D6AA6474"
				+ "A464AE4934663C5265BA7018BA091F78");
		OctetString hash = new OctetString();

		Assert.assertEquals("", hash.toString());

		// validate with wrong pvt, validation should return false
		boolean validate = Eccsi.validateSigningKeys(IDENTIFIER_RFC, badPvt, KPAK_RFC,
				SSK_RFC, hash);

		Assert.assertFalse(validate);
		Assert.assertNotEquals("", hash.toString());
	}

	@Test
	public void testValidateSigningKeysBadKpak() throws Exception {
		// last charachter changed 4 -> 5
		OctetString badKpak = OctetString.fromHex("04"
				+ "50D4670BDE75244F28D2838A0D25558A" + "7A72686D4522D4C8273FB6442AEBFA93"
				+ "DBDD37551AFD263B5DFD617F3960C65A"
				+ "8C298850FF99F20366DCE7D4367217F5");
		OctetString hash = new OctetString();

		Assert.assertEquals("", hash.toString());

		// validate with wrong kpak, validation should return false
		boolean validate = Eccsi.validateSigningKeys(IDENTIFIER_RFC, PVT_RFC, badKpak,
				SSK_RFC, hash);

		Assert.assertFalse(validate);
		Assert.assertNotEquals("", hash.toString());
	}

	@Test
	public void testValidateSigningKeysBadSsk() throws Exception {
		// last charachter changed D -> B
		OctetString badSsk = OctetString.fromHex(
				"23F374AE1F4033F3E9DBDDAAEF20F4CF0B86BBD5A138A5AE9E7E006B34489A0B");
		OctetString hash = new OctetString();

		Assert.assertEquals("", hash.toString());

		// validate with wrong ssk, validation should return false
		boolean validate = Eccsi.validateSigningKeys(IDENTIFIER_RFC, PVT_RFC, KPAK_RFC,
				badSsk, hash);

		Assert.assertFalse(validate);
		Assert.assertNotEquals("", hash.toString());
	}

	@Test
	public void testSignOK() throws Exception {
		testValidateSigningKeysOkRfcParams();

		OctetString signature = Eccsi.sign(SIGN_MESSAGE, PVT_RFC, SSK_RFC, this.hash,
				new RandomGeneratorTestImpl());

		Assert.assertEquals(SIGNATURE, signature);
	}

	@Test
	public void testSignEmptyHash() {
		OctetString signature = null;

		// test with empty hash
		try {
			signature = Eccsi.sign(SIGN_MESSAGE, PVT_RFC, SSK_RFC, this.hash,
					new RandomGeneratorTestImpl());
		}
		catch (IllegalArgumentException exception) {
			Assert.assertEquals(EMPTY_HASH_MESSAGE, exception.getMessage());
		}
	}

	@Test
	public void testSignBadHash() {
		// last charachter changed 1 -> 2
		OctetString wrongHash = OctetString.fromHex(
				"490F3FEBBC1C902F6289723D7F8CBF79DB88930849D19F38F0295B5C276C14D2");

		// test with wrong hash
		OctetString signature = Eccsi.sign(SIGN_MESSAGE, PVT_RFC, SSK_RFC, wrongHash,
				new RandomGeneratorTestImpl());

		Assert.assertNotEquals(SIGNATURE, signature);
	}

	@Test
	public void testSignBadPvt() throws Exception {
		// last charachter changed 9 -> 8
		OctetString badPvt = OctetString.fromHex("04" + "758A142779BE89E829E71984CB40EF75"
				+ "8CC4AD775FC5B9A3E1C8ED52F6FA36D9" + "A79D247692F4EDA3A6BDAB77D6AA6474"
				+ "A464AE4934663C5265BA7018BA091F78");
		testValidateSigningKeysOkRfcParams();

		// test with wrong pvt
		OctetString signature = Eccsi.sign(SIGN_MESSAGE, badPvt, SSK_RFC, this.hash,
				new RandomGeneratorTestImpl());

		Assert.assertNotEquals(SIGNATURE, signature);
	}

	@Test
	public void testSignBadSsk() throws Exception {
		// last charachter changed D -> B
		OctetString badSsk = OctetString.fromHex(
				"23F374AE1F4033F3E9DBDDAAEF20F4CF0B86BBD5A138A5AE9E7E006B34489A0B");
		testValidateSigningKeysOkRfcParams();

		// test with wrong pvt
		OctetString signature = Eccsi.sign(SIGN_MESSAGE, PVT_RFC, badSsk, this.hash,
				new RandomGeneratorTestImpl());

		Assert.assertNotEquals(SIGNATURE, signature);
	}

	@Test
	public void testVerify() {
		boolean valid = Eccsi.verify(SIGN_MESSAGE, SIGNATURE, IDENTIFIER_RFC, KPAK_RFC);

		Assert.assertTrue(valid);
	}

	@Test
	public void testVerifyMessageChanged() {
		OctetString changedMessage = OctetString.fromAscii("wrong\0");
		OctetString changedMessage2 = OctetString.fromAscii("messagea\0");
		OctetString changedMessage3 = OctetString.fromAscii("messag\0");

		boolean valid = Eccsi.verify(changedMessage, SIGNATURE, IDENTIFIER_RFC, KPAK_RFC);
		Assert.assertFalse(valid);

		valid = Eccsi.verify(changedMessage2, SIGNATURE, IDENTIFIER_RFC, KPAK_RFC);
		Assert.assertFalse(valid);

		valid = Eccsi.verify(changedMessage3, SIGNATURE, IDENTIFIER_RFC, KPAK_RFC);
		Assert.assertFalse(valid);
	}

	@Test
	public void testVerifyBadIdentifier() {
		OctetString badIdentifier = OctetString.fromAscii("2011-01\0tel:+447700900123\0");

		boolean valid = Eccsi.verify(SIGN_MESSAGE, SIGNATURE, badIdentifier, KPAK_RFC);
		Assert.assertFalse(valid);
	}

	@Test
	public void testVefiryBadKpak() {
		// last charachter changed 4 -> 5
		OctetString badKpak = OctetString.fromHex("04"
				+ "50D4670BDE75244F28D2838A0D25558A" + "7A72686D4522D4C8273FB6442AEBFA93"
				+ "DBDD37551AFD263B5DFD617F3960C65A"
				+ "8C298850FF99F20366DCE7D4367217F5");

		boolean valid = Eccsi.verify(SIGN_MESSAGE, SIGNATURE, IDENTIFIER_RFC, badKpak);
		Assert.assertFalse(valid);
	}

	@Test
	public void testSignAndVerify() throws Exception {
		OctetString identifier = createIdentifier();

		OctetString hash = new OctetString();
		boolean validSsk = Eccsi.validateSigningKeys(identifier, PVT_KMS, KPAK_KMS,
				SSK_KMS, hash);
		Assert.assertTrue(validSsk);

		OctetString signature = Eccsi.sign(SIGN_MESSAGE, PVT_KMS, SSK_KMS, hash,
				new RandomGeneratorTestImpl());

		boolean validSignature = Eccsi.verify(SIGN_MESSAGE, signature, identifier,
				KPAK_KMS);
		Assert.assertTrue(validSignature);
	}

	private OctetString createIdentifier() {
		return new OctetString(MikeySakkeUid.generateUid(MCPTT_ID, KMS_URI,
				KEY_PERIOD_LENGHT, KEY_PERIOD_OFFSET, CURRENT_KEY_PERIOD_NO).getBytes());
	}

}
