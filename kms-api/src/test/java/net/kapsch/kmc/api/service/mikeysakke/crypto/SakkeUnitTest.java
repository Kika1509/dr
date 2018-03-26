package net.kapsch.kmc.api.service.mikeysakke.crypto;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import net.kapsch.kms.api.mikeysakke.crypto.Sakke;
import net.kapsch.kms.api.mikeysakke.crypto.SakkeException;
import net.kapsch.kms.api.mikeysakke.crypto.SakkeParameterSet1;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.RandomGenerator;
import net.kapsch.kms.api.mikeysakke.utils.RandomGeneratorImpl;
import net.kapsch.kms.api.util.MikeySakkeUid;

// TODO it takes too long for automatic testing
public class SakkeUnitTest {

	// test data from core, KmsInitExample10.xml nad KMSKeyProvExample10.xml
	private final static String MCPTT_ID = "test4@example.org";

	private final static String KMS_URI = "kms.example.org";

	private final static int KEY_PERIOD_LENGHT = 2419200;

	private final static int KEY_PERIOD_OFFSET = 0;

	private final static int CURRENT_KEY_PERIOD_NO = 1540;

	private final static OctetString KMS_PUBLIC_Z = OctetString.fromHex(
			"046AA4FBC0DC1C9D16F5ABB00540BB8E4A119478ADFA5846C3CDE03E79E689BB24E282C1A1AE05841DA0167FDE90B1C8EEEF77BF3975F59306B02E9408512162774C72371C0BAA0339D1B85200E87FD3AC9A40B93B07A26D10519199851E48A43B67D33307DEF9B45B048E4C5D01A007611C01775AD99AB839471F50A79AD42F1A5EAEFA1DC7EED78F76AFE707A11BFC9772E9CA98A2E0956C31CE4D03191A0714594002A042F65F1344E60501F6659B913C4FAC096C0571896718B29884C38F9C968DD51EEE106DCE8257159BD1934286C4C0EEFA0EB6D60ACE4C2F0FD4D1B686A39DB44CFCC548E9E4E0144EA732B4805C1BEDF5CE309C0C97005A7D46A03BC1");

	private final static OctetString RSK = OctetString.fromHex(
			"0461C39C1DC1DB350088C89768458003FC0C3B344F02E5A307ED9582C8EC2D1C3CD59E15046E25E16B8FC0B0B915F1F98175806A0C0863B938251B4D0528BC021F606E70960FB4301E229C89CD12D7125ACA168EF9788472E9F0D2A0CD361B44CEA3C1C79D9BD84056442742A98193CA0D3A739CDE0EE93EBFF83C85E310132BCF6529A28599ED2DBE0B063FD7F095B18CC41B376B718839B642201626EF726393BD4A0AC385EA0ECC000E35C0CEB356A9D6E7832FC7115AFBD3755967F1180B505D17418BABD35C2F35F529A85F5FC23CEA490452B406C49800AE251EB9E92C9C9A352ACEB8B7BD5902184DAFA238E41FD34779B6CFD55F1D27875990D82A7518");

	// RFC test data, https://tools.ietf.org/html/rfc6507
	private static final OctetString IDENTIFIER_RFC = OctetString
			.fromAscii("2011-02\0tel:+447700900123\0");

	private static final OctetString KMS_PUBLIC_Z_RFC = OctetString.fromHex("04"
			+ "5958EF1B1679BF099B3A030DF255AA6A" + "23C1D8F143D4D23F753E69BD27A832F3"
			+ "8CB4AD53DDEF4260B0FE8BB45C4C1FF5" + "10EFFE300367A37B61F701D914AEF097"
			+ "24825FA0707D61A6DFF4FBD7273566CD" + "DE352A0B04B7C16A78309BE640697DE7"
			+ "47613A5FC195E8B9F328852A579DB8F9" + "9B1D0034479EA9C5595F47C4B2F54FF2" +

			"1508D37514DCF7A8E143A6058C09A6BF" + "2C9858CA37C258065AE6BF7532BC8B5B"
			+ "63383866E0753C5AC0E72709F8445F2E" + "6178E065857E0EDA10F68206B63505ED"
			+ "87E534FB2831FF957FB7DC619DAE6130" + "1EEACC2FDA3680EA4999258A833CEA8F"
			+ "C67C6D19487FB449059F26CC8AAB655A" + "B58B7CC796E24E9A394095754F5F8BAE");

	private static final OctetString RSK_RFC = OctetString.fromHex("04"
			+ "93AF67E5007BA6E6A80DA793DA300FA4" + "B52D0A74E25E6E7B2B3D6EE9D18A9B5C"
			+ "5023597BD82D8062D34019563BA1D25C" + "0DC56B7B979D74AA50F29FBF11CC2C93"
			+ "F5DFCA615E609279F6175CEADB00B58C" + "6BEE1E7A2A47C4F0C456F05259A6FA94"
			+ "A634A40DAE1DF593D4FECF688D5FC678" + "BE7EFC6DF3D6835325B83B2C6E69036B"
			+ "155F0A27241094B04BFB0BDFAC6C670A" + "65C325D39A069F03659D44CA27D3BE8D"
			+ "F311172B554160181CBE94A2A783320C" + "ED590BC42644702CF371271E496BF20F"
			+ "588B78A1BC01ECBB6559934BDD2FB65D" + "2884318A33D1A42ADF5E33CC5800280B"
			+ "28356497F87135BAB9612A1726042440" + "9AC15FEE996B744C332151235DECB0F5");
	private final static OctetString EXPECTED_SED_RFC = OctetString.fromHex("04"
			+ "44E8AD44AB8592A6A5A3DDCA5CF896C7" + "18043606A01D650DEF37A01F37C228C3"
			+ "32FC317354E2C274D4DAF8AD001054C7" + "6CE57971C6F4486D5723043261C506EB"
			+ "F5BE438F53DE04F067C776E0DD3B71A6" + "290133283725A532F21AF145126DC1D7"
			+ "77ECC27BE50835BD28098B8A73D9F801" + "D893793A41FF5C49B87E79F2BE4D56CE"
			+ "557E134AD85BB1D4B9CE4F8BE4B08A12" + "BABF55B1D6F1D7A638019EA28E15AB1C"
			+ "9F76375FDD1210D4F4351B9A009486B7" + "F3ED46C965DED2D80DADE4F38C6721D5"
			+ "2C3AD103A10EBD2959248B4EF006836B" + "F097448E6107C9EDEE9FB704823DF199"
			+ "F832C905AE45F8A247A072D8EF729EAB" + "C5E27574B07739B34BE74A532F747B86"
			+ "89E0BC661AA1E91638E6ACC84E496507");
	private final static OctetString EXPETCED_SSV_RFC = OctetString
			.fromHex("123456789abcdef0123456789abcdef0");
	private static final int paramSet = 1;
	private int parameterSet;

	private OctetString createIdentifier() {
		return new OctetString(MikeySakkeUid.generateUid(MCPTT_ID, KMS_URI,
				KEY_PERIOD_LENGHT, KEY_PERIOD_OFFSET, CURRENT_KEY_PERIOD_NO).getBytes());
	}

	@Before
	public void setup() {
		this.parameterSet = new SakkeParameterSet1().parameterSetIdentifer();
	}

	@Test
	public void testValidateReceiverSecretKey() {
		boolean validation = Sakke.validateReceiverSecretKey(IDENTIFIER_RFC,
				KMS_PUBLIC_Z_RFC, RSK_RFC, this.parameterSet);
		Assert.assertTrue("RSK validation failed", validation);
	}

	// testing generateSharedSecretAndSED method

	@Test
	public void testValidateRSKIncorrectID() {
		OctetString badID = OctetString.fromAscii("2011-02\0tel:+447700900124\0");

		boolean validated = Sakke.validateReceiverSecretKey(badID, KMS_PUBLIC_Z_RFC,
				RSK_RFC, this.parameterSet);
		Assert.assertFalse("RSK passed validation with badID", validated);
	}

	@Test
	public void testValidateRSKIncorrectKMSPublicZ() {
		OctetString badKMSPublicZString = OctetString.fromHex("04"
				+ "5958EF1B1679BF099B3A030DF255AA6A" + "23C1D8F143D4D23F753E69BD27A832F3"
				+ "8CB4AD53DDEF4260B0FE8BB45C4C1FF5" + "10EFFE300367A37B61F701D914AEF097"
				+ "24825FA0707D61A6DFF4FBD7273566CD" + "DE352A0B04B7C16A78309BE640697DE7"
				+ "47613A5FC195E8B9F328852A579DB8F9" + "9B1D0034479EA9C5595F47C4B2F54FF2"
				+

				"1508D37514DCF7A8E143A6058C09A6BF" + "2C9858CA37C258065AE6BF7532BC8B5B"
				+ "63383866E0753C5AC0E72709F8445F2E" + "6178E065857E0EDA10F68206B63505ED"
				+ "87E534FB2831FF957FB7DC619DAE6130" + "1EEACC2FDA3680EA4999258A833CEA8F"
				+ "C67C6D19487FB449059F26CC8AAB655A"
				+ "B58B7CC796E24E9A394095754F5F8BAF");

		boolean validated = Sakke.validateReceiverSecretKey(IDENTIFIER_RFC,
				badKMSPublicZString, RSK_RFC, this.parameterSet);
		Assert.assertFalse("RSK passed validation with bad KMS Public Z string",
				validated);
	}

	@Test
	public void testValidateRSKIncorrectRSK() {
		OctetString badRSKString = OctetString.fromHex("04"
				+ "93AF67E5007BA6E6A80DA793DA300FA4" + "B52D0A74E25E6E7B2B3D6EE9D18A9B5C"
				+ "5023597BD82D8062D34019563BA1D25C" + "0DC56B7B979D74AA50F29FBF11CC2C93"
				+ "F5DFCA615E609279F6175CEADB00B58C" + "6BEE1E7A2A47C4F0C456F05259A6FA94"
				+ "A634A40DAE1DF593D4FECF688D5FC678" + "BE7EFC6DF3D6835325B83B2C6E69036B"
				+ "155F0A27241094B04BFB0BDFAC6C670A" + "65C325D39A069F03659D44CA27D3BE8D"
				+ "F311172B554160181CBE94A2A783320C" + "ED590BC42644702CF371271E496BF20F"
				+ "588B78A1BC01ECBB6559934BDD2FB65D" + "2884318A33D1A42ADF5E33CC5800280B"
				+ "28356497F87135BAB9612A1726042440"
				+ "9AC15FEE996B744C332151235DECB0FA");

		boolean validated = Sakke.validateReceiverSecretKey(IDENTIFIER_RFC,
				KMS_PUBLIC_Z_RFC, badRSKString, this.parameterSet);
		Assert.assertFalse("RSK passed validation with bad RSK string", validated);
	}

	@Test
	public void testGenerateAndExtractSSV() {
		OctetString id = createIdentifier();
		OctetString sed = new OctetString();
		OctetString ssv = Sakke.generateSharedSecretAndSED(sed, id, 1, KMS_PUBLIC_Z,
				new RandomGeneratorImpl());
		System.out.println(
				"sed: " + sed + "\nid: " + id + "\nKMS_PUBLIC_Z: " + KMS_PUBLIC_Z);

		OctetString ssvExtracted = Sakke.extractSharedSecret(sed, id, 1, RSK,
				KMS_PUBLIC_Z);
		System.out.println("sed: " + sed + "\nid: " + id + "\nRSK: " + RSK
				+ "\nKMS_PUBLIC_Z: " + KMS_PUBLIC_Z);

		Assert.assertEquals(ssv, ssvExtracted);
	}

	@Test
	public void testGenerateAndExtractSsvRfc() {
		OctetString sed = new OctetString();
		OctetString ssv = Sakke.generateSharedSecretAndSED(sed, IDENTIFIER_RFC,
				this.parameterSet, KMS_PUBLIC_Z_RFC, new RandomGeneratorImpl());

		OctetString ssvExtracted = Sakke.extractSharedSecret(sed, IDENTIFIER_RFC,
				this.parameterSet, RSK_RFC, KMS_PUBLIC_Z_RFC);

		Assert.assertEquals(ssv, ssvExtracted);
	}

	@Test
	public void testGenerateSharedSecretAndSED() {
		RandomGenerator r = new SsvRandomGenerator();
		OctetString validation = new OctetString();
		long time1 = System.currentTimeMillis();
		OctetString ssv = Sakke.generateSharedSecretAndSED(validation, IDENTIFIER_RFC,
				this.parameterSet, KMS_PUBLIC_Z_RFC, r);
		long time2 = System.currentTimeMillis();
		System.out.println(time2 - time1);

		Assert.assertTrue("Generated SED does not match expected",
				validation.equals(EXPECTED_SED_RFC));
		Assert.assertTrue("Generated SSV does not match expected",
				ssv.equals(EXPETCED_SSV_RFC));
	}

	@Test
	public void testGenerateSharedSecretAndSEDIncorrectID() {
		OctetString badID = OctetString.fromAscii("2011-02\0tel:+447700900124\0");
		RandomGenerator r = new SsvRandomGenerator();
		OctetString validation = new OctetString();
		OctetString ssv = Sakke.generateSharedSecretAndSED(validation, badID,
				this.parameterSet, KMS_PUBLIC_Z_RFC, r);

		Assert.assertFalse("Generated SED matches expected but with bad ID",
				validation.equals(EXPECTED_SED_RFC));
		Assert.assertTrue("Generated SSV does not match expected",
				ssv.equals(EXPETCED_SSV_RFC));
	}

	// testing extractSharedSecret method

	@Test
	public void testGenerateSharedSecretAndSEDIncorrectKMSPublicZ() {
		RandomGenerator r = new SsvRandomGenerator();
		OctetString badKMSPublicZString = OctetString.fromHex("04"
				+ "5958EF1B1679BF099B3A030DF255AA6A" + "23C1D8F143D4D23F753E69BD27A832F3"
				+ "8CB4AD53DDEF4260B0FE8BB45C4C1FF5" + "10EFFE300367A37B61F701D914AEF097"
				+ "24825FA0707D61A6DFF4FBD7273566CD" + "DE352A0B04B7C16A78309BE640697DE7"
				+ "47613A5FC195E8B9F328852A579DB8F9" + "9B1D0034479EA9C5595F47C4B2F54FF2"
				+ "1508D37514DCF7A8E143A6058C09A6BF" + "2C9858CA37C258065AE6BF7532BC8B5B"
				+ "63383866E0753C5AC0E72709F8445F2E" + "6178E065857E0EDA10F68206B63505ED"
				+ "87E534FB2831FF957FB7DC619DAE6130" + "1EEACC2FDA3680EA4999258A833CEA8F"
				+ "C67C6D19487FB449059F26CC8AAB655A"
				+ "B58B7CC796E24E9A394095754F5F8BAF");

		OctetString validation = new OctetString();
		OctetString ssv = Sakke.generateSharedSecretAndSED(validation, IDENTIFIER_RFC,
				this.parameterSet, badKMSPublicZString, r);

		Assert.assertFalse("Generated SED matches expected but with a badZ",
				validation.equals(EXPECTED_SED_RFC));
		Assert.assertTrue("Generated SSV does not match expected",
				ssv.equals(EXPETCED_SSV_RFC));
	}

	@Test
	public void testExtractSharedSecret() {
		OctetString bobSSV = Sakke.extractSharedSecret(EXPECTED_SED_RFC, IDENTIFIER_RFC,
				this.parameterSet, RSK_RFC, KMS_PUBLIC_Z_RFC);

		Assert.assertTrue("Extracted SSV does not match expected",
				bobSSV.equals(EXPETCED_SSV_RFC));
	}

	@Test(expected = SakkeException.class)
	public void testExtractSharedSecretIncorrectSED() {
		OctetString badSED = OctetString
				.fromHex("04" + "310c9f91e3433aed68429a062ad283d86d4"
						+ "a0a8579eaab57b68ef9f1ae0c4949b4457c"
						+ "ce67eff4e6a36c6e9041a8cb922af84984e"
						+ "b100f96c89a9a694efcf34bfd09635e9e3c"
						+ "1d27c4a5eafd72c2a60e702563ebf80cba3"
						+ "109d18879fd026d34840190109f1df4d95d"
						+ "75fbc241ca50fbd2588634178b727f8e621"
						+ "a41a643dd354ceef51a8f5937ac7a2395ae"
						+ "c0721038bafd59b204f0f226891cafff346"
						+ "8ba22d14c4482a2926f4cbb4958a15324c8"
						+ "480bdaaa02ed57ca174267e0762376213f2"
						+ "a9485985204f05a440dd28445e202a5e8d4"
						+ "97499b2d021cae17627f7ecb31a696c0893"
						+ "58b6250b128c2abaddd740266d190ee7d43"
						+ "a37ee6702a420a729abc953b9ee35632ef0" + "92a0931bd9210fe8bAB");
		OctetString validation = Sakke.extractSharedSecret(badSED, IDENTIFIER_RFC,
				this.parameterSet, RSK_RFC, KMS_PUBLIC_Z_RFC);
	}

	@Test(expected = SakkeException.class)
	public void testExtractSharedSecretIncorrectID() {
		OctetString badID = OctetString.fromAscii("2011-02\0tel:+447700900124\0");

		OctetString validation = Sakke.extractSharedSecret(EXPECTED_SED_RFC, badID,
				this.parameterSet, RSK_RFC, KMS_PUBLIC_Z_RFC);
	}

	@Test(expected = SakkeException.class)
	public void testExtractSharedSecretIncorrectZTest() {
		OctetString badKMSPublicZString = OctetString.fromHex("04"
				+ "5958EF1B1679BF099B3A030DF255AA6A" + "23C1D8F143D4D23F753E69BD27A832F3"
				+ "8CB4AD53DDEF4260B0FE8BB45C4C1FF5" + "10EFFE300367A37B61F701D914AEF097"
				+ "24825FA0707D61A6DFF4FBD7273566CD" + "DE352A0B04B7C16A78309BE640697DE7"
				+ "47613A5FC195E8B9F328852A579DB8F9" + "9B1D0034479EA9C5595F47C4B2F54FF2"
				+ "1508D37514DCF7A8E143A6058C09A6BF" + "2C9858CA37C258065AE6BF7532BC8B5B"
				+ "63383866E0753C5AC0E72709F8445F2E" + "6178E065857E0EDA10F68206B63505ED"
				+ "87E534FB2831FF957FB7DC619DAE6130" + "1EEACC2FDA3680EA4999258A833CEA8F"
				+ "C67C6D19487FB449059F26CC8AAB655A"
				+ "B58B7CC796E24E9A394095754F5F8BAF");

		OctetString validation = Sakke.extractSharedSecret(EXPECTED_SED_RFC,
				IDENTIFIER_RFC, this.parameterSet, RSK_RFC, badKMSPublicZString);
	}

	// testing getParam method

	@Test
	public void testExtractSharedSecretIncorrectParam() {
		Assert.assertFalse("Parameter set must be 1", this.parameterSet != 1);

	}

	@Test
	public void testGetParamSet() {
		SakkeParameterSet1 sakkeTestSET = Sakke.getParamSet(paramSet);

		Assert.assertEquals(1, sakkeTestSET.parameterSetIdentifer());
	}

	class SsvRandomGenerator implements RandomGenerator {
		@Override
		public OctetString generate(final int n) {

			return OctetString.fromHex("123456789ABCDEF0123456789ABCDEF0");
		}
	}

}
