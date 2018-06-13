package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import net.kapsch.kmc.api.service.exceptions.ClientException;
import net.kapsch.kmc.api.service.exceptions.KmsServerInternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.kapsch.kmc.api.service.mikey.GenericId;
import net.kapsch.kmc.api.service.mikey.MikeyException;
import net.kapsch.kmc.api.service.mikey.MikeySakkeIMessage;
import net.kapsch.kmc.api.service.mikey.Payload;
import net.kapsch.kmc.api.service.mikey.PayloadGeneralExtension;
import net.kapsch.kmc.api.service.mikey.PayloadGeneralExtensionData;
import net.kapsch.kmc.api.service.mikey.PayloadHDR;
import net.kapsch.kmc.api.service.mikey.PayloadIDR;
import net.kapsch.kmc.api.service.mikey.PayloadRAND;
import net.kapsch.kmc.api.service.mikey.PayloadSAKKE;
import net.kapsch.kmc.api.service.mikey.PayloadSIGN;
import net.kapsch.kmc.api.service.mikey.PayloadSP;
import net.kapsch.kmc.api.service.mikey.PayloadT;
import net.kapsch.kmc.api.service.mikey.PolicyParam;
import net.kapsch.kmc.api.service.mikey.tables.GeneralExtensionStatus;
import net.kapsch.kmc.api.service.mikey.tables.IDRole;
import net.kapsch.kmc.api.service.mikey.tables.IDType;
import net.kapsch.kmc.api.service.mikey.tables.NextPayload;
import net.kapsch.kmc.api.service.mikey.tables.SRTPDefaultProfile;
import net.kapsch.kmc.api.service.mikey.tables.SType;
import net.kapsch.kms.api.KmsCertificateType;
import net.kapsch.kms.api.KmsKeySetType;
import net.kapsch.kms.api.KmsResponseType;
import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.encryption.aes.AesCbcEncryption;
import net.kapsch.kms.api.mikeysakke.PurposeTag;
import net.kapsch.kms.api.mikeysakke.crypto.Eccsi;
import net.kapsch.kms.api.mikeysakke.crypto.EccsiException;
import net.kapsch.kms.api.mikeysakke.crypto.Sakke;
import net.kapsch.kms.api.mikeysakke.crypto.SakkeParameterSet1;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.RandomGeneratorImpl;
import net.kapsch.kms.api.time.TimeUtils;
import net.kapsch.kms.api.util.KeyUtils;
import net.kapsch.kms.api.util.MikeySakkeUid;
import net.kapsch.kms.api.util.Utils;

public class Client {

	private static final Logger log = LoggerFactory.getLogger(Client.class);

	private static final int CONN_COUNT = 10;

	/**
	 * The user's URI (e.g. user.001@mcptt.example.org).
	 */
	private String mcpttId;

	/**
	 * The user's Kms URI (e.g. kms.example.org).
	 */
	private String kmsMcpttId;

	/** Service for communication with Kms Server. */
	private ApiService apiService;
	/**
	 * The DomainKeyData object that holds client's keys provisioned by kms. They are
	 * permanent.
	 */
	private DomainKeyData domainKeys;
	/**
	 * The UserKeyData object that holds client's keys provisioned by another client. They
	 * are temporary.
	 */
	private UserKeyData userKeys;

	/**
	 * Client constructor, sets the client's field variables. Access Token is permanent
	 * and already set in ApiService object and because of that this is primary used for
	 * testing.
	 *
	 * @param mcpttId - client's Mcptt Id
	 * @param apiService - service for communication with kms
	 */
	public Client(final String mcpttId, final ApiService apiService) {
		this.apiService = apiService;
		this.mcpttId = mcpttId;
	}

	/**
	 * Initialization method of client. It must be called before any other action because
	 * it fetches keys from KMS.
	 */
	public void init() throws JAXBException, IOException, XMLStreamException {
		initClient();
		keyProvClient();
	}

	/**
	 * Method for key provisioning of domain keys for user.
	 */
	private void initClient() throws JAXBException, IOException, XMLStreamException {
		KmsResponseType initResponse = null;

		int times = 0;
		while (times != CONN_COUNT) {
			try {
				initResponse = this.apiService.initialize();
				break;
			}
			catch (KmsServerInternalException e) {
				times++;
			}
		}

		KmsCertificateType certificate = initResponse.getKmsMessage().getKmsInit()
				.getKmsCertificate();
		this.kmsMcpttId = initResponse.getKmsUri();

		this.domainKeys = new DomainKeyData(new OctetString(certificate.getPubAuthKey()),
				new OctetString(certificate.getPubEncKey()),
				certificate.getUserKeyPeriod().intValue(),
				certificate.getUserKeyOffset().intValue());
	}

	/**
	 * Method for key provisioning of user keys.
	 */
	private void keyProvClient() throws JAXBException, IOException, XMLStreamException {
		KmsResponseType keyProvResponse = null;

		int times = 0;
		while (times != CONN_COUNT) {
			try {
				keyProvResponse = this.apiService.keyProvision();
				break;
			}
			catch (KmsServerInternalException e) {
				times++;
			}
		}

		KmsKeySetType kmsKeySetType = keyProvResponse.getKmsMessage().getKmsKeyProv()
				.getKmsKeySet().get(0);

		this.userKeys = new UserKeyData(
				new OctetString(kmsKeySetType.getUserPubTokenPVT().getValue()),
				new OctetString(kmsKeySetType.getUserDecryptKey().getValue()),
				new OctetString(kmsKeySetType.getUserSigningKeySSK().getValue()));
	}


	/**
	 * First generate GMK and then with that key generate Group call MIKEY-SAKKE
	 * I_MESSAGE. See Sakke.class method generateSharedSecretAndSED(...) and Client.class
	 * method generateGroupCallRequest(...)
	 *
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 * @param mcpttGroupId - Mcptt Group Identifier
	 * @param activationTime - activationTime
	 * @param text - plaintext
	 *
	 * @return Group call request which contains MIKEY-SAKKE I_MESSAGE, GMK, GMK-ID and
	 * optional params (mcpttGroupId, activationTime, text)
	 *
	 * @throws Exception - throws Exception
	 */
	public GroupCallRequest generateGroupCallRequest(String targetMcpttId,
			String initiatorKmsMcpttId, String targetKmsMcpttId, byte[] mcpttGroupId,
			byte[] activationTime, byte[] text) throws Exception {
		OctetString gmkEncData = new OctetString();

		OctetString gmk = Sakke.generateSharedSecretAndSED(gmkEncData,
				getUid(targetMcpttId.getBytes(), targetKmsMcpttId.getBytes()),
				this.domainKeys.getSakkeParameterSetIndex(),
				this.domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());

		int gmkId = KeyUtils.generateKeyIdentifier(PurposeTag.GMK);

		MikeySakkeIMessage iMessage = generateGroupCallMikeyMessage(gmk.getOctets(),
				gmkId, gmkEncData, targetMcpttId, initiatorKmsMcpttId, targetKmsMcpttId,
				mcpttGroupId, activationTime, text);

		return new GroupCallRequest(new KeyPair(gmk.getOctets(), gmkId), iMessage,
				mcpttGroupId, activationTime, text);
	}

	/**
	 * Generation of a group key transport message (encapsulation of GMK). See
	 * specification 3GPP 33.179 version 13.4.0 (section 7.3.1-1). GMK can be generated by
	 * Sakke.class method generateSharedSecretAndSED(...)
	 *
	 * The concatenated 'MCPTT group ID', 'Activation time', 'Text', 'Reserved' and
	 * 'Random padding' elements shall be encrypted using AES-128 in Cipher Block Chaining
	 * mode using the IV (16 octets) as Initial Vector, as described in IETF RFC 3602
	 * [23]. The encryption key shall be the GMK. See specification 3GPP 33.179 version
	 * 13.4.0 (section E.6.8 Cryptography).
	 *
	 * @param gmk - GMK (Shared Secret Value)
	 * @param encapsulatedGmk - encrypted GMK
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 * @param mcpttGroupId - Mcptt Group Identifier
	 * @param activationTime - activationTime
	 * @param text - plaintext
	 *
	 * @return MikeySakkeIMessage object which represents the Group Key Transport payload
	 *
	 * @throws MikeyException - throws MikeyException
	 * @throws IOException - throws IOException
	 * @throws NoSuchPaddingException - throws NoSuchPaddingException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IllegalBlockSizeException - throws IllegalBlockSizeException
	 * @throws BadPaddingException - throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException - throws
	 * InvalidAlgorithmParameterException
	 */
	public MikeySakkeIMessage generateGroupCallMikeyMessage(byte[] gmk, int gmkId,
			OctetString encapsulatedGmk, String targetMcpttId, String initiatorKmsMcpttId,
			String targetKmsMcpttId, byte[] mcpttGroupId, byte[] activationTime,
			byte[] text) throws Exception {
		log.info("Creating Group call MIKEY-SAKKE I_MESSAGE ...");
		int userSalt = KeyUtils.generateUserSalt(targetMcpttId, gmk);
		int gukId = generateGukId(gmkId, userSalt);

		PolicyParam[] policyParams = SRTPDefaultProfile.getGroupCallPolicyParams();

		MikeySakkeIMessage iMessage = createMikeySakkeIMessage(targetMcpttId,
				initiatorKmsMcpttId, targetKmsMcpttId, encapsulatedGmk.getOctets(), gukId,
				policyParams);

		// add encrypted General Extension Parameters
		PayloadGeneralExtension payloadGeneralExtension = new PayloadGeneralExtension();
		SecretKey secretKey = Aes.getSecretKey(gmk);
		PayloadGeneralExtensionData data = new PayloadGeneralExtensionData(mcpttGroupId,
				activationTime, text);
		byte[] encryptedParams = AesCbcEncryption.encrypt(
				Utils.getBytesFromBits(data.getEncoded()), secretKey,
				payloadGeneralExtension.getIv());
		payloadGeneralExtension.setData(encryptedParams);

		iMessage.getPayload(NextPayload.SAKKE).setNextPayload(NextPayload.GENERAL_EXT);
		iMessage.addPayload(payloadGeneralExtension);

		log.info("Group call MIKEY-SAKKE I_MESSAGE created.");

		return signMikeySakkeIMessage(iMessage);
	}

	/**
	 * Processing of a group key transport message (extraction of GMK). See specification
	 * 3GPP 33.179 version 13.4.0 (section 7.3.1-2).
	 *
	 * @param iMessage - MIKEY-SAKKE I_MESSAGE
	 *
	 * @return Group call request which contains GMK, GMK-ID and optional params
	 * (mcpttGroupId, activationTime, text)
	 *
	 * @throws BadPaddingException - throws BadPaddingException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IllegalBlockSizeException - throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException - throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException - throws
	 * InvalidAlgorithmParameterException
	 * @throws IOException - throws IOException
	 */
	public GroupCallRequest processGroupKeyTransportMessage(MikeySakkeIMessage iMessage)
			throws Exception {
		log.info("Processing Group call MIKEY-SAKKE I_MESSAGE ...");

		// extract user's URI from the initiator field (IDRi)
		byte[] idri = iMessage.extractIDR(IDRole.IDR_I);
		byte[] idrKmsi = iMessage.extractIDR(IDRole.IDR_KMS_I);

		// exctract signature from payload
		byte[] signature = ((PayloadSIGN) iMessage.getPayload(NextPayload.SIGN))
				.getSignature();

		// validate signature
		boolean valid = Eccsi.verify(
				new OctetString(iMessage.getEncodedWithoutSignature()),
				new OctetString(signature), getUid(idri, idrKmsi),
				this.domainKeys.getPublicAuthenticationKey());

		// if signature valid, extract GMK
		byte[] gmk;
		if (valid) {
			byte[] sakkeData = ((PayloadSAKKE) iMessage.getPayload(NextPayload.SAKKE))
					.getSakkeData();
			gmk = Sakke.extractSharedSecret(new OctetString(sakkeData), getUid(),
					this.domainKeys.getSakkeParameterSetIndex(),
					this.userKeys.getReceiverSecretKey(),
					this.domainKeys.getKmsPublicKey()).getOctets();
		}
		else {
			throw new EccsiException("Validation of signature failed.");
		}

		// xors the GUK-ID and User Salt together to extract the GMK-ID
		int gukId = iMessage.getHDRPayload().getCsbId();
		int userSalt = KeyUtils.generateUserSalt(this.mcpttId, gmk);
		int gmkId = Utils.xor(gukId, userSalt);

		// decrypt and extract General Extension Parameters
		PayloadGeneralExtension extension = (PayloadGeneralExtension) iMessage
				.getPayload(NextPayload.GENERAL_EXT);

		SecretKey secretKey = Aes.getSecretKey(gmk);
		byte[] decryptedParams = AesCbcEncryption.decrypt(extension.getData(), secretKey,
				extension.getIv());
		extension.setData(decryptedParams);
		PayloadGeneralExtensionData extensionData = PayloadGeneralExtensionData
				.decode(extension.getData());

		byte[] decryptedMcpttGroupId = Utils
				.getBytesFromBits(extensionData.getMcpttGroupId());
		byte[] decryptedActivationtime = extensionData.getActivationTime();
		byte[] decryptedText = Utils.getBytesFromBits(extensionData.getText());

		// If the Status field in the GMK parameters indicate the GMK has been revoked,
		// the GMK and GMK-ID shall not be used.
		if (extensionData.getStatus() == GeneralExtensionStatus.REVOKED) {
			throw new ClientException("GMK has been revoked.");
		}

		return new GroupCallRequest(new KeyPair(gmk, gmkId), null, decryptedMcpttGroupId,
				decryptedActivationtime, decryptedText);
	}

	/**
	 * Generation of the GUK-ID. See specification 3GPP 33.179 version 13.4.0 (section
	 * 7.3.1-3). The User Salt is xor'd with the 28 least-significant bits of the GMK-ID
	 * to create the 32-bit GUK-ID. The GUK-ID is placed in the CSB ID field within the
	 * header of the I_MESSAGE.
	 *
	 * @param gmkId - GMK Identifier (GMK-ID)
	 * @param userSalt - 28-bit User Salt by hashing the user's MCPTT ID through a KDF
	 * using the GMK as the key
	 *
	 * @return Group User Key Identifier (GUK-ID)
	 */
	public int generateGukId(int gmkId, int userSalt) {
		// The 4 most significant bites of User Salt are 0, so xor will just make a copy
		// of Purpose tag (the 4 most significant bites of GMK ID)
		return Utils.xor(gmkId, userSalt);
	}

	/**
	 * Compose MIKEY-SAKKE I_MESSAGE containing SAKKE Encapsulated Data and a signature
	 * which will be sent to Responder in order to establish a secure media session with
	 * him.
	 *
	 * I_MESSAGE = HDR, T, RAND, [IDRi], [IDRr], [IDRkmsi], [IDRkmsr], [CERT], {SP},
	 * SAKKE, SIGN
	 *
	 * @param responderMcpttId - responder's Mcptt Id (IDRr)
	 * @param initiatorsKmsMcpttId - initiatorsKms Mcptt Id (IDRkmsi)
	 * @param respondersKmsMcpttId - respondersKms Mcptt Id (IDRkmsr)
	 * @param sakkeData - sakke payload, encrypted Shared Secret Value (SSV)
	 * @param csbId - csb id for Common Header Payload (HDR), (e.g. pck-id, gkm-id, ...)
	 * @param policyParams - the security properties for Security Policy payload (SP)
	 *
	 * @return MikeySakkeIMessage object which represent MIKEY-SAKKE I_MESSAGE
	 *
	 * @throws MikeyException - throws MikeyException
	 */
	public MikeySakkeIMessage createMikeySakkeIMessage(String responderMcpttId,
			String initiatorsKmsMcpttId, String respondersKmsMcpttId, byte[] sakkeData,
			Integer csbId, PolicyParam[] policyParams) throws MikeyException {

		PayloadHDR payloadHDR = new PayloadHDR(csbId, new GenericId());

		PayloadT payloadT = new PayloadT(
				TimeUtils.fromNtpEpochTo(LocalDateTime.now()).ntpValue());

		SecureRandom ranGen = new SecureRandom();
		byte[] rand = new byte[PayloadRAND.DEFAULT_RAND_LEN];
		ranGen.nextBytes(rand);
		PayloadRAND payloadRAND = new PayloadRAND(NextPayload.IDR, rand);

		PayloadIDR payloadIDRi = new PayloadIDR(NextPayload.IDR, IDRole.IDR_I, IDType.URI,
				this.mcpttId.getBytes());

		PayloadIDR payloadIDRr = new PayloadIDR(NextPayload.IDR, IDRole.IDR_R, IDType.URI,
				responderMcpttId.getBytes());

		PayloadIDR payloadIDRkmsi = new PayloadIDR(NextPayload.IDR, IDRole.IDR_KMS_I,
				IDType.URI, initiatorsKmsMcpttId.getBytes());

		PayloadIDR payloadIDRkmsr = new PayloadIDR(NextPayload.SP, IDRole.IDR_KMS_R,
				IDType.URI, respondersKmsMcpttId.getBytes());

		PayloadSP payloadSP = new PayloadSP(policyParams,
				PayloadSP.calculateLength(policyParams));

		byte sakkeParams = (byte) new SakkeParameterSet1().parameterSetIdentifer();
		byte sakkeIdScheme = 1;
		PayloadSAKKE payloadSAKKE = new PayloadSAKKE(NextPayload.SIGN, sakkeParams,
				sakkeIdScheme, sakkeData);

		// create MIKEY-SAKKE I_MESSAGE
		Payload[] payloads = { payloadHDR, payloadT, payloadRAND, payloadIDRi,
				payloadIDRr, payloadIDRkmsi, payloadIDRkmsr, payloadSP, payloadSAKKE };

		return new MikeySakkeIMessage(payloads);

	}

	/**
	 * Sign the MIKEY-SAKKE I_MESSAGE.
	 *
	 * @param iMessage - MIKEY-SAKKE I_MESSAGE to be signed
	 *
	 * @return - signed MIKEY-SAKKE I_MESSAGE
	 *
	 * @throws MikeyException - throws MikeyException
	 */
	public MikeySakkeIMessage signMikeySakkeIMessage(MikeySakkeIMessage iMessage)
			throws Exception {

		// validation of SSK
		OctetString hash = new OctetString();
		boolean validSsk = Eccsi.validateSigningKeys(getUid(),
				this.userKeys.getPublicValidationToken(),
				this.domainKeys.getPublicAuthenticationKey(),
				this.userKeys.getSecretSigningKey(), hash);

		if (!validSsk) {
			throw new EccsiException("Validation of SSK failed!");
		}
		this.userKeys.setHS(hash);

		log.info("Signing MIKEY-SAKKE I_MESSAGE ...");

		// creating signature
		OctetString signature = Eccsi.sign(new OctetString(iMessage.getEncoded()),
				this.userKeys.getPublicValidationToken(),
				this.userKeys.getSecretSigningKey(), this.userKeys.getHS(),
				new RandomGeneratorImpl());
		PayloadSIGN payloadSIGN = new PayloadSIGN(SType.ECCSI, signature.getOctets());

		// add signature to MIKEY-SAKKE I_MESSAGE
		iMessage.addPayload(payloadSIGN);

		return iMessage;
	}

	/**
	 * Generate UID for this User.
	 *
	 * @return UID
	 */
	public OctetString getUid() {
		return this.getUid(this.mcpttId.getBytes(), this.kmsMcpttId.getBytes());
	}

	/**
	 * Generate UID from user's URI, user's KMS URI and monthly key periods.
	 *
	 * @param mcpttId - user's URI
	 * @param kmsMcpttId - user's KMS URI
	 *
	 * @return UID
	 */
	public OctetString getUid(byte[] mcpttId, byte[] kmsMcpttId) {
		String uid = MikeySakkeUid.generateUid(new String(mcpttId),
				new String(kmsMcpttId), this.domainKeys.getUserKeyPeriod(),
				this.domainKeys.getUserKeyOffset(), 1542);
		return new OctetString(uid.getBytes());
	}

	/**
	 * @return the DomainKeyData object that stores this client's keys provisioned by kms
	 */
	public DomainKeyData getDomainKeys() {
		return domainKeys;
	}

	public void setDomainKeys(DomainKeyData domainKeys) {
		this.domainKeys = domainKeys;
	}

	/**
	 * @return the DomainKeyData object that stores this client's keys provisioned another
	 * client
	 */
	public UserKeyData getUserKeys() {
		return userKeys;
	}

	public void setUserKeys(UserKeyData userKeys) {
		this.userKeys = userKeys;
	}

	public String getKmsMcpttId() {
		return this.kmsMcpttId;
	}

	public String getMcpttId() {
		return this.mcpttId;
	}

	public ApiService getApiService() {
		return this.apiService;
	}
}
