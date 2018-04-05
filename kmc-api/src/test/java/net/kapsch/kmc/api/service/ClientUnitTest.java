package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import com.google.common.io.ByteStreams;

import info.solidsoft.mockito.java8.api.WithBDDMockito;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import net.kapsch.kmc.api.service.mikey.MikeyException;
import net.kapsch.kmc.api.service.mikey.MikeySakkeIMessage;
import net.kapsch.kmc.api.service.mikey.PayloadSAKKE;
import net.kapsch.kmc.api.service.mikey.PolicyParam;
import net.kapsch.kmc.api.service.mikey.tables.IDRole;
import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kmc.api.service.mikey.tables.SRTPDefaultProfile;
import net.kapsch.kms.api.DefaultMarshallerService;
import net.kapsch.kms.api.MarshallerService;
import net.kapsch.kms.api.mikeysakke.PurposeTag;
import net.kapsch.kms.api.mikeysakke.crypto.Sakke;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.RandomGeneratorImpl;
import net.kapsch.kms.api.util.KeyUtils;
import net.kapsch.kms.api.util.MikeySakkeUid;

public class ClientUnitTest implements WithBDDMockito {

	private final static String INIT_MCPTT_ID = "test3@example.org";

	private final static String TARGET_MCPTT_ID = "test4@example.org";

	private final static String KMS_URI = "kms.example.org";

	private final static int KEY_PERIOD_LENGHT = 2419200;

	private final static int KEY_PERIOD_OFFSET = 0;

	private final static int CURRENT_KEY_PERIOD_NO = 1541;

	private final static OctetString KPAK = OctetString.fromHex(
			"042CFB4C1003B36E2F7B211E9BC28CEBE2B41A0CCD4EBEA6F4EA2A4EFFD4D7144204972AECF92453255AC6E1ABEB21852F100C88EF87803F93F5A210A01000322B");

	private final static OctetString KMS_PUBLIC_Z = OctetString.fromHex(
			"044A42095E2DBEF7C804F303DDE0AB3B1449ACBAC68B9FB48DD80E777B937E01BE665F9397C3149EF0EF5FD6E902592C5C136542FAFF74475F9AB68B450549E83AFA214350DDA752D8AE8E8A96999E08B01637141B03997DAE0C7091B0D96C3DE405D58538E029997D8B616E956F412023F2E239C61068136BB07524F7D8644D0C13E4EA1349B7D3DED7C04CD25B809CF82784AC6685C9AD73CF8EA667D9794A41C1C83A37E934768D57D760D44F30EF784F216393C3E2F9AB68099BC4AA82AD29C8DA090B1AA95D493FB7C19C39F1E869C95FE0950CA53A68EE330EDFC9E055D62202CC0419282EE96C30C9B5239E832056FC112EE5CDDE811D5AF523123DE7C6");

	private final static OctetString INIT_PVT = OctetString.fromHex(
			"04265CB23E15E412054A27FA7B9F9F551B6D563CD5245BFB59B635CB0225DD3D8401C97B0DD84A677DD4E7E85D9630050F63974E50D5F47044F7504AF1184822F8");

	private final static OctetString INIT_SSK = OctetString
			.fromHex("BDFF7D4338ADB3C29545272B3813A5CC0D1E6FCC00CAB616F65E4629D6AA58E8");

	private final static OctetString INIT_RSK = OctetString.fromHex(
			"0459198FFDB50F3C604A12F92DBB608BC988E594EE7D2BB28344EB35C60F6CFB7725F7997289028CF0FF0AA711AC68DF131850D30816B8AC05BBDFEAEAB016B564CB803A8966A732BB544944BBCA0A856764BFC3A1811146BE3B05AA35457D86067BF69FF608918B6BD4C9D329389E468906FB5BB1C5C97CF2687D81699240F8224F7E06DA4C75090A1462B94D36E5EE777A7A017603DD4F68693BE025850A4EC2CBC6E2B407A8F434A9C0085A738F11F504AA229DDB787F70157936F136BEE26326A1A4A03A20457A31D430C31082444486786746802FA505291C878B9DEEB9ACC2A79D0ED376DF7D5384A70CE290C6D3CF1E1001624A677605ABA0249C7D10DF");

	private final static OctetString TARGET_PVT = OctetString.fromHex(
			"04E70B3D3F6709C76ABA349D91B9B82FB7BCDC2EF063655830293BAF6000A2E3D91A1D35B7DAB54CAD1C00A953C20CD79428BEF29FF21E8AE91963BD978587CDD5");

	private final static OctetString TARGET_SSK = OctetString
			.fromHex("240656AE7440D1597A3598158517A0355FB58CDF717B9013E5D038FA4E751834");

	private final static OctetString TARGET_RSK = OctetString.fromHex(
			"0475ACBF340C8791EDB882E0E2EBD080D5C619100E9C5E1246C0EC084120488FBDBCA508A51DF07A8C5B9F3B8415863EA052F575CB8F2BE78F597E61B5DFA8F96F024E0AAEB4060C6F59C72B7FE5DF31764BD73F0F9FD050315C5025262E6DB8ED3FFC2B179076BC459B0F1CE4C6886F7FE7CCF3C6C4CBDE109AA2C6C8878A4B600B65D13AD31755C2D9A41133024036947553C9FC0C2499D4A4BC881717FD1525CF324204291E5BD01787A73204A1C60DE5C0934C3851EC12F4EF1C25960F5D1C21A4418A679B98AB13BE7B49A2FB35DE4C20403A81C9CC113DDED218A2854E065017FFC68BB720561CB3736BE44DE163E9389AB853579D8013493659C497C229");

	private Client initClient;
	private Client targetClient;
	private MarshallerService marshallerService;

	@Mock
	private ApiService apiService;

	private String getXmlData(String path) throws IOException {
		InputStream resourceAsStream = this.getClass().getResourceAsStream(path);
		byte[] data = ByteStreams.toByteArray(resourceAsStream);
		return new String(data);
	}

	@Before
	public void setup()
			throws JAXBException, IOException, XMLStreamException, JSONException {
		MockitoAnnotations.initMocks(this);
		this.marshallerService = new DefaultMarshallerService();

		// keys from xml are overwritten, this is just because instantiating the client
		when(apiService.initialize()).thenReturn(this.marshallerService
				.unmarshalKmsResponseType(getXmlData("/xml/KMSInitExample.xml")));
		when(apiService.keyProvision()).thenReturn(this.marshallerService
				.unmarshalKmsResponseType(getXmlData("/xml/KMSKeyProvExample.xml")));

		this.initClient = new Client(INIT_MCPTT_ID, this.apiService);
		this.initClient.init();
		this.initClient.setUserKeys(new UserKeyData(INIT_PVT, INIT_RSK, INIT_SSK));
		this.initClient.setDomainKeys(new DomainKeyData(KPAK, KMS_PUBLIC_Z,
				KEY_PERIOD_LENGHT, KEY_PERIOD_OFFSET));

		this.targetClient = new Client(TARGET_MCPTT_ID, this.apiService);
		this.targetClient.init();
		this.targetClient
				.setUserKeys(new UserKeyData(TARGET_PVT, TARGET_RSK, TARGET_SSK));
		this.targetClient.setDomainKeys(new DomainKeyData(KPAK, KMS_PUBLIC_Z,
				KEY_PERIOD_LENGHT, KEY_PERIOD_OFFSET));
	}

	@Test
	public void testCreateMikeySakkeIMessage() throws MikeyException {
		String responderMcpttId = "responder@example.org";
		String initiatorsKmsMcpttId = "initiator@example.org";
		String respondersKmsMcpttId = "responderKms@example.org";
		byte[] sakkeData = Hex.decode(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		int csbId = 1;
		PolicyParam[] policyParams = SRTPDefaultProfile.getPrivateCallPolicyParams();

		MikeySakkeIMessage iMessage = this.initClient.createMikeySakkeIMessage(
				responderMcpttId, initiatorsKmsMcpttId, respondersKmsMcpttId, sakkeData,
				csbId, policyParams);

		byte[] encodedIMessage = iMessage.getEncoded();

		MikeySakkeIMessage decodedIMessage = MikeySakkeIMessage.decode(encodedIMessage);

		Assert.assertEquals(this.initClient.getMcpttId(),
				new String(decodedIMessage.extractIDR(IDRole.IDR_I)));
		Assert.assertEquals(initiatorsKmsMcpttId,
				new String(decodedIMessage.extractIDR(IDRole.IDR_KMS_I)));
		Assert.assertEquals(responderMcpttId,
				new String(decodedIMessage.extractIDR(IDRole.IDR_R)));
		Assert.assertEquals(respondersKmsMcpttId,
				new String(decodedIMessage.extractIDR(IDRole.IDR_KMS_R)));
		Assert.assertTrue(Arrays.equals(sakkeData,
				((PayloadSAKKE) decodedIMessage.getPayload(NextPayload.SAKKE))
						.getSakkeData()));
		Assert.assertEquals(csbId,
				((PayloadSAKKE) decodedIMessage.getPayload(NextPayload.SAKKE))
						.getIdScheme());
		for (int i = 0; i < policyParams.length; i++) {
			Assert.assertEquals(policyParams[i].toString(),
					SRTPDefaultProfile.getPrivateCallPolicyParams()[i].toString());
		}
	}

	@Test
	@Ignore
	public void testSignMikeySakkeIMessage() throws Exception {
		byte[] sakkeData = Hex.decode(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
		int csbId = 1;
		PolicyParam[] policyParams = SRTPDefaultProfile.getPrivateCallPolicyParams();
		byte[] key = Hex.decode("06a9214036b8a15b512e03d534120006");

		MikeySakkeIMessage iMessage = this.initClient.createMikeySakkeIMessage(
				TARGET_MCPTT_ID, INIT_MCPTT_ID, KMS_URI, sakkeData, csbId, policyParams);
		int payloadSizeBefore = iMessage.getPayloads().length;
		Assert.assertNull(iMessage.getPayload(NextPayload.SIGN));

		MikeySakkeIMessage signedIMessage = this.initClient
				.signMikeySakkeIMessage(iMessage);

		Assert.assertEquals(payloadSizeBefore, signedIMessage.getPayloads().length - 1);
		Assert.assertNotNull(signedIMessage.getPayload(NextPayload.SIGN));
	}

	@Test
	public void testGenerateGukId()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		String mcpttId = "mcptt1@op1.com";
		byte[] gmk = Hex.decode(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

		int userSalt = KeyUtils.generateUserSalt(mcpttId, gmk);
		int gmkId = KeyUtils.generateKeyIdentifier(PurposeTag.GMK);

		int gukId = this.initClient.generateGukId(gmkId, userSalt);
		int gukIdXOR = gukId ^ userSalt;

		Assert.assertEquals(gmkId, gukIdXOR);
	}

	@Test
	public void srtpDerivationWithKfcTest()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] kfc = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] kfcRand = OctetString.hexStringToByteArray(
				"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
		int kfcId = 12345;

		SrtpKeys result = initClient.srtpDerivationWithKfc(kfc, kfcRand, kfcId);

		SrtpKeys wantedResult = new SrtpKeys(OctetString.hexStringToByteArray(
				"9cbb85bf9ea4dfa08eb02456a8e2890ab525249ba5e504e15f205ead8bfc4366"),
				OctetString.hexStringToByteArray(
						"aa8128b705846786f32e03aeddbe4bdf498e6bc9d237d496d348f92d26c46788"),
				kfcId);

		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpSalt())),
				new String(Hex.encode(result.getSrtpSalt())));
		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpMaster())),
				new String(Hex.encode(result.getSrtpMaster())));
		Assert.assertEquals(wantedResult.getMki(), result.getMki());
	}

	@Test
	public void srtpDerivationWithPckTest()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] pck = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] pckRand = OctetString.hexStringToByteArray(
				"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
		int csId = 12345;
		int pckId = 56789;

		SrtpKeys result = initClient.srtpDerivationWithPck(pck, pckRand, pckId, csId);

		SrtpKeys wantedResult = new SrtpKeys(OctetString.hexStringToByteArray(
				"17e4949fc178cb293499c3c6c78e627cc235ce292fe89d9f60b5048a85446362"),
				OctetString.hexStringToByteArray(
						"0da3db1b6cfce48fc850f7fc00f6fbfbeef823e11b29a1301d98497c7f1bf170"),
				pckId);

		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpSalt())),
				new String(Hex.encode(result.getSrtpSalt())));
		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpMaster())),
				new String(Hex.encode(result.getSrtpMaster())));
		Assert.assertEquals(wantedResult.getMki(), result.getMki());
	}

	@Test
	public void srtpDerivationWithMscck()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] mscck = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] mscckRand = OctetString.hexStringToByteArray(
				"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
		int csId = 12345;
		int mscckId = 56789;

		SrtpKeys result = initClient.srtpDerivationWithMscck(mscck, mscckRand, mscckId,
				csId);

		SrtpKeys wantedResult = new SrtpKeys(OctetString.hexStringToByteArray(
				"17e4949fc178cb293499c3c6c78e627cc235ce292fe89d9f60b5048a85446362"),
				OctetString.hexStringToByteArray(
						"0da3db1b6cfce48fc850f7fc00f6fbfbeef823e11b29a1301d98497c7f1bf170"),
				mscckId);

		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpSalt())),
				new String(Hex.encode(result.getSrtpSalt())));
		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpMaster())),
				new String(Hex.encode(result.getSrtpMaster())));
		Assert.assertEquals(wantedResult.getMki(), result.getMki());
	}

	@Test
	public void srtpDerivationWithGmkTest()
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		byte[] gmk = OctetString.hexStringToByteArray(
				"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] gmkRand = OctetString.hexStringToByteArray(
				"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
		int csId = 12345;
		int gukId = 56789;

		SrtpKeys result = initClient.srtpDerivationWithGmk(gmk, gmkRand, gukId, csId);

		SrtpKeys wantedResult = new SrtpKeys(OctetString.hexStringToByteArray(
				"17e4949fc178cb293499c3c6c78e627cc235ce292fe89d9f60b5048a85446362"),
				OctetString.hexStringToByteArray(
						"0da3db1b6cfce48fc850f7fc00f6fbfbeef823e11b29a1301d98497c7f1bf170"),
				12346);

		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpSalt())),
				new String(Hex.encode(result.getSrtpSalt())));
		Assert.assertEquals(new String(Hex.encode(wantedResult.getSrtpMaster())),
				new String(Hex.encode(result.getSrtpMaster())));
		Assert.assertFalse(result.getMki() == 0);
	}

	@Test
	@Ignore
	public void testGeneratePrivateCallMikeyMessage() throws Exception {
		OctetString pckEncData = new OctetString();
		OctetString targetIdentifier = createIdentifier(TARGET_MCPTT_ID, KMS_URI);

		OctetString pck = Sakke.generateSharedSecretAndSED(pckEncData, targetIdentifier,
				this.initClient.getDomainKeys().getSakkeParameterSetIndex(), KMS_PUBLIC_Z,
				new RandomGeneratorImpl());

		int pckId = KeyUtils.generateKeyIdentifier(PurposeTag.PCK);

		MikeySakkeIMessage iMessage = this.initClient.generatePrivateCallMikeyMessage(
				pckEncData.getOctets(), pckId, TARGET_MCPTT_ID, KMS_URI, KMS_URI);

		KeyPair pckPair = this.targetClient.processPrivateCallRequest(iMessage);

		Arrays.equals(pck.getOctets(), pckPair.getKey());
	}

	@Test
	@Ignore
	public void testGeneratePrivateCallRequest() throws Exception {
		String targetMcpttId = TARGET_MCPTT_ID;

		PrivateCallRequest request = this.initClient
				.generatePrivateCallRequest(targetMcpttId, KMS_URI, KMS_URI);

		KeyPair pckPair = this.targetClient
				.processPrivateCallRequest(request.getMikeySakkeIMessage());

		Arrays.equals(request.getKeyPair().getKey(), pckPair.getKey());
	}

	@Test
	@Ignore
	public void testGenerateGroupCallMikeyMessage() throws Exception {
		OctetString gmkEncData = new OctetString();
		String targetMcpttId = TARGET_MCPTT_ID;
		OctetString targetIdentifier = createIdentifier(targetMcpttId, KMS_URI);
		byte[] mcpptGroupId = ("mcpptGroupId").getBytes();
		byte[] activationTime = ("activate").getBytes();
		byte[] text = ("text").getBytes();

		OctetString gmk = Sakke.generateSharedSecretAndSED(gmkEncData, targetIdentifier,
				this.initClient.getDomainKeys().getSakkeParameterSetIndex(), KMS_PUBLIC_Z,
				new RandomGeneratorImpl());

		int gmkId = KeyUtils.generateKeyIdentifier(PurposeTag.GMK);

		MikeySakkeIMessage iMessage = this.initClient.generateGroupCallMikeyMessage(
				gmk.getOctets(), gmkId, gmkEncData, targetMcpttId, KMS_URI, KMS_URI,
				mcpptGroupId, activationTime, null);

		GroupCallRequest request = this.targetClient
				.processGroupKeyTransportMessage(iMessage);

		Arrays.equals(gmk.getOctets(), request.getKeyPair().getKey());
	}

	@Test
	@Ignore
	public void testGenerateGroupCallRequest() throws Exception {
		String targetMcpttId = TARGET_MCPTT_ID;
		byte[] mcpptGroupId = ("mcpptGroupId").getBytes();
		byte[] activationTime = ("activate").getBytes();
		byte[] text = ("text").getBytes();

		GroupCallRequest request = this.initClient.generateGroupCallRequest(targetMcpttId,
				KMS_URI, KMS_URI, mcpptGroupId, activationTime, text);

		GroupCallRequest receivedRequest = this.targetClient
				.processGroupKeyTransportMessage(request.getMikeySakkeIMessage());

		Arrays.equals(request.getKeyPair().getKey(),
				receivedRequest.getKeyPair().getKey());
	}

	@Test
	@Ignore
	public void testMBMSSubchannelControlMessage() throws Exception {
		OctetString mscckEncData = new OctetString();
		String targetMcpttId = TARGET_MCPTT_ID;
		OctetString targetIdentifier = createIdentifier(targetMcpttId, KMS_URI);

		OctetString mscck = Sakke.generateSharedSecretAndSED(mscckEncData,
				targetIdentifier,
				this.initClient.getDomainKeys().getSakkeParameterSetIndex(), KMS_PUBLIC_Z,
				new RandomGeneratorImpl());

		int mscckId = KeyUtils.generateKeyIdentifier(PurposeTag.MSCCK);

		MikeySakkeIMessage iMessage = this.initClient
				.generateMBMSSubchannelControlMessage(mscckEncData.getOctets(), mscckId,
						targetMcpttId, KMS_URI, KMS_URI);

		KeyPair mscckPair = this.targetClient
				.processMBMSSubchannelControlMessage(iMessage);

		Arrays.equals(mscck.getOctets(), mscckPair.getKey());
	}

	@Test
	@Ignore
	public void testMBMSSubchannelControlRequest() throws Exception {
		String targetMcpttId = TARGET_MCPTT_ID;

		MBMSSubchannelControlRequest request = this.initClient
				.generateMBMSSubchannelControlRequest(targetMcpttId, KMS_URI, KMS_URI);

		KeyPair keyPair = this.targetClient
				.processMBMSSubchannelControlMessage(request.getMikeySakkeIMessage());

		Arrays.equals(request.getKeyPair().getKey(), keyPair.getKey());
	}

	private OctetString createIdentifier(String mcpttId, String kmsUri) {
		return new OctetString(MikeySakkeUid.generateUid(mcpttId, kmsUri,
				KEY_PERIOD_LENGHT, KEY_PERIOD_OFFSET, CURRENT_KEY_PERIOD_NO).getBytes());
	}

}
