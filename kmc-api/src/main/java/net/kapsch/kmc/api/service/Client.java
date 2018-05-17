package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import net.kapsch.kmc.api.service.exceptions.KmsServerInternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

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
import net.kapsch.kmc.api.service.mikey.utils.KeyDerivationPrf;
import net.kapsch.kms.api.KmsCertificateType;
import net.kapsch.kms.api.KmsKeySetType;
import net.kapsch.kms.api.KmsResponseType;
import net.kapsch.kms.api.encryption.XmlEncryption;
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
import net.kapsch.kms.api.util.XmlUtils;

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
	 * First generate PCK and then with that key generate Private call MIKEY-SAKKE
	 * I_MESSAGE. See Sakke.class method generateSharedSecretAndSED(...) and Client.class
	 * method generatePrivateCallRequest(...)
	 *
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 *
	 * @return Private call request which contains MIKEY-SAKKE I_MESSAGE, PCK and PCK-ID
	 *
	 * @throws Exception - throws Exception
	 */
	public PrivateCallRequest generatePrivateCallRequest(String targetMcpttId,
			String targetKmsMcpttId, String initiatorKmsMcpttId) throws Exception {
		log.info("Creating Private call request ...");
		OctetString pckEncData = new OctetString();

		OctetString pck = Sakke.generateSharedSecretAndSED(pckEncData,
				getUid(targetMcpttId.getBytes(), targetKmsMcpttId.getBytes()),
				this.domainKeys.getSakkeParameterSetIndex(),
				this.domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());

		int pckId = KeyUtils.generateKeyIdentifier(PurposeTag.PCK);

		MikeySakkeIMessage iMessage = generatePrivateCallMikeyMessage(
				pckEncData.getOctets(), pckId, targetMcpttId, targetKmsMcpttId,
				initiatorKmsMcpttId);

		return new PrivateCallRequest(new KeyPair(pck.getOctets(), pckId), iMessage);
	}

	/**
	 * Generation of a private call MIKEY-SAKKE I_MESSAGE for Private call key
	 * distribution. See specification 3GPP 33.179 version 13.4.0 (section 7.4.1-1). PCK
	 * can be generated by Sakke.class method generateSharedSecretAndSED(...)
	 *
	 * @param encapsulatedPCK - encapsulated PCK, encrypted Shared Secret Value (SSV)
	 * @param pckId - PCK-ID key identifier of PCK(SSV)
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 *
	 * @return MIKEY-SAKKE I_MESSAGE
	 *
	 * @throws MikeyException - throws MikeyException
	 */
	public MikeySakkeIMessage generatePrivateCallMikeyMessage(byte[] encapsulatedPCK,
			int pckId, String targetMcpttId, String targetKmsMcpttId,
			String initiatorKmsMcpttId) throws Exception {
		log.info("Creating Private call MIKEY-SAKKE I_MESSAGE ...");

		PolicyParam[] policyParams = SRTPDefaultProfile.getPrivateCallPolicyParams();

		MikeySakkeIMessage iMessage = createMikeySakkeIMessage(targetMcpttId,
				initiatorKmsMcpttId, targetKmsMcpttId, encapsulatedPCK, pckId,
				policyParams);

		return signMikeySakkeIMessage(iMessage);
	}

	/**
	 * Processing of private call request for Private call key distribution. See
	 * specification 3GPP 33.179 version 13.4.0 (section 7.4.1-2)
	 *
	 * @param iMessage - MikeySakkeIMessage object which represent MIKEY-SAKKE I_MESSAGE
	 *
	 * @return - PCK with associate PCK-ID
	 */
	public KeyPair processPrivateCallRequest(MikeySakkeIMessage iMessage) {
		log.info("Processing Private call MIKEY-SAKKE I_MESSAGE ...");
		return processKeyDistributionControlMessage(iMessage);
	}

	/**
	 * First generate CSK and then generate Client To Server request which contains
	 * MIKEY-SAKKE I_MESSAGE for distribution of CSK.
	 *
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 *
	 * @return Client To Server request which contains MIKEY-SAKKE I_MESSAGE, CSK and
	 * CSK-ID
	 *
	 * @throws Exception - throws Exception
	 */
	public ClientToServerRequest generateClientToServerRequest(String targetMcpttId,
			String targetKmsMcpttId, String initiatorKmsMcpttId) throws Exception {
		log.info("Creating Client To Server request ...");
		OctetString cskEncData = new OctetString();

		OctetString csk = Sakke.generateSharedSecretAndSED(cskEncData,
				getUid(targetMcpttId.getBytes(), targetKmsMcpttId.getBytes()),
				this.domainKeys.getSakkeParameterSetIndex(),
				this.domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());

		int cskId = KeyUtils.generateKeyIdentifier(PurposeTag.CSK);

		MikeySakkeIMessage iMessage = generateClientToServerMikeyMessage(
				cskEncData.getOctets(), cskId, targetMcpttId, targetKmsMcpttId,
				initiatorKmsMcpttId);

		return new ClientToServerRequest(new KeyPair(csk.getOctets(), cskId), iMessage);
	}

	/**
	 * Generation of a client to server MIKEY-SAKKE I MESSAGE for distribution of CSK. See
	 * specification 3GPP 33.179 version 13.4.0 (section 9.1). CSK can be generated by
	 * Sakke.class method generateSharedSecretAndSED(...)
	 *
	 * @param encapsulatedCSK - encapsulated CSK, encrypted Shared Secret Value (SSV)
	 * @param cskId - CSK-ID key identifier of CSK(SSV)
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 *
	 * @return MIKEY-SAKKE I_MESSAGE
	 *
	 * @throws MikeyException - throws MikeyException
	 */
	public MikeySakkeIMessage generateClientToServerMikeyMessage(byte[] encapsulatedCSK,
			int cskId, String targetMcpttId, String targetKmsMcpttId,
			String initiatorKmsMcpttId) throws Exception {
		log.info("Creating Client To Server MIKEY-SAKKE I_MESSAGE ...");

		PolicyParam[] policyParams = SRTPDefaultProfile.getPrivateCallPolicyParams();

		MikeySakkeIMessage iMessage = createMikeySakkeIMessage(targetMcpttId,
				initiatorKmsMcpttId, targetKmsMcpttId, encapsulatedCSK, cskId,
				policyParams);

		return signMikeySakkeIMessage(iMessage);
	}

	/**
	 * Processing of Client To Server request for distribution of CSK. See specification
	 * 3GPP 33.179 version 13.4.0 (section 9.1)
	 *
	 * @param iMessage - MikeySakkeIMessage object which represent MIKEY-SAKKE I_MESSAGE
	 *
	 * @return - CSK with associate CSK-ID
	 */
	public KeyPair processClientToServerRequest(MikeySakkeIMessage iMessage) {
		log.info("Processing Client To Server MIKEY-SAKKE I_MESSAGE ...");
		return processKeyDistributionControlMessage(iMessage);
	}

	/**
	 * First generate MSCCK and then with that key generate MBMS subchannel control
	 * message. See Sakke.class method generateSharedSecretAndSED(...) and Client.class
	 * method generateMBMSSubchannelControlMessage(...)
	 *
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 *
	 * @return Private call request which contains MIKEY-SAKKE I_MESSAGE, MSCCK and
	 * MSCCK-ID
	 *
	 * @throws Exception - throws Exception
	 */
	public MBMSSubchannelControlRequest generateMBMSSubchannelControlRequest(
			String targetMcpttId, String targetKmsMcpttId, String initiatorKmsMcpttId)
			throws Exception {
		log.info("Creating MBMS Subchannel Control request ...");
		OctetString mscckEncData = new OctetString();

		OctetString mscck = Sakke.generateSharedSecretAndSED(mscckEncData,
				getUid(targetMcpttId.getBytes(), targetKmsMcpttId.getBytes()),
				this.domainKeys.getSakkeParameterSetIndex(),
				this.domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());

		int mscckId = KeyUtils.generateKeyIdentifier(PurposeTag.MSCCK);

		MikeySakkeIMessage iMessage = generateMBMSSubchannelControlMessage(
				mscckEncData.getOctets(), mscckId, targetMcpttId, targetKmsMcpttId,
				initiatorKmsMcpttId);

		return new MBMSSubchannelControlRequest(new KeyPair(mscck.getOctets(), mscckId),
				iMessage);
	}

	/**
	 * Generation MBMS subchannel control message for key distribution. See specification
	 * 3GPP 33.179 version 13.4.0 (section 7.7.2-1).
	 *
	 * @param encapsulatedMSCCK - encrypted MBMS subchannel control key (MSCCK)
	 * @param targetMcpttId - responder's Mcptt Id (IDRr)
	 * @param targetKmsMcpttId - responder's kms Mcptt Id (IDRKmsr)
	 * @param initiatorKmsMcpttId - initiator's kms Mcptt Id (IDRKmsi)
	 *
	 * @return - MIKEY-SAKKE I_MESSAGE
	 *
	 * @throws MikeyException - throws MikeyException
	 */
	public MikeySakkeIMessage generateMBMSSubchannelControlMessage(
			byte[] encapsulatedMSCCK, int mscckId, String targetMcpttId,
			String targetKmsMcpttId, String initiatorKmsMcpttId) throws Exception {
		log.info("Creating MBMS Subchannel Control MIKEY-SAKKE I_MESSAGE ...");

		PolicyParam[] policyParams = SRTPDefaultProfile.getGroupCallPolicyParams();

		MikeySakkeIMessage iMessage = createMikeySakkeIMessage(targetMcpttId,
				initiatorKmsMcpttId, targetKmsMcpttId, encapsulatedMSCCK, mscckId,
				policyParams);

		return signMikeySakkeIMessage(iMessage);
	}

	/**
	 * Processing of of MBMS subchannel control message for key distribution. See
	 * specification 3GPP 33.179 version 13.4.0 (section 7.7.2-2)
	 *
	 * @param iMessage - MikeySakkeIMessage object which represent MIKEY-SAKKE I_MESSAGE
	 *
	 * @return - MBMS subchannel control key (MSCCK) with associate MSCCK-ID
	 */
	public KeyPair processMBMSSubchannelControlMessage(MikeySakkeIMessage iMessage) {
		log.info("Processing MBMS Subchannel Control MIKEY-SAKKE I_MESSAGE ...");
		return processKeyDistributionControlMessage(iMessage);
	}

	/**
	 * Processing of MIKEY-SAKKE I_MESSAGE and extracting key pair (key and key
	 * identifier).
	 *
	 * @param iMessage - MikeySakkeIMessage object which represent MIKEY-SAKKE I_MESSAGE
	 *
	 * @return key (e.g. PCK, MSCCK) and key identifier (e.g. PCK-ID, MSCCK-ID)
	 */
	private KeyPair processKeyDistributionControlMessage(MikeySakkeIMessage iMessage) {
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

		int keyId = iMessage.getHDRPayload().getCsbId();

		// if signature valid, extract key (PCK, MSCCK, ...)
		if (valid) {
			byte[] sakkeData = ((PayloadSAKKE) iMessage.getPayload(NextPayload.SAKKE))
					.getSakkeData();
			byte[] key = Sakke.extractSharedSecret(new OctetString(sakkeData), getUid(),
					this.domainKeys.getSakkeParameterSetIndex(),
					this.userKeys.getReceiverSecretKey(),
					this.domainKeys.getKmsPublicKey()).getOctets();

			return new KeyPair(key, keyId);
		}
		else {
			throw new EccsiException("Validation of signature failed.");
		}
	}

	/**
	 * SRTP/SRTCP Key Derivation for media stream protection. See specification 3GPP
	 * 33.179 version 13.4.0 (section 7.3.6-1). TGK from GMK
	 *
	 * @param gmk - used as the MIKEY Traffic Generating Key (TGK)
	 * @param rand - (at least) 128-bit (pseudo-)random bit-string sent by the Initiator
	 * in the initial exchange.
	 * @param gukId - used as Crypto Session Bundle ID (32-bits unsigned integer)
	 * @param csId - the Crypto Session ID (8-bits unsigned integer)
	 *
	 * @return - Master and salt SRTP keys, MKI
	 *
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IOException - throws IOException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 */

	public SrtpKeys srtpDerivationWithGmk(byte[] gmk, byte[] rand, int gukId, int csId)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException {
		int gmkId = KeyUtils.generateKeyIdentifier(PurposeTag.GMK);
		int mki = Utils.xor(gmkId, gukId); // todo . The MKI should be a 64-bit value
											// formed by concatenating the GMK-ID with the
											// GUK-ID (GMK-ID || GUK-ID).

		return KeyDerivationPrf.derivationMasterAndSaltKey(gmk, rand, gukId, csId, mki);
	}

	/**
	 * SRTCP Key Derivation. See specification 3GPP 33.179 version 13.4.0 (section 7.7.3).
	 * TGK from MSCCK
	 *
	 * @param mscck - used as the MIKEY Traffic Generating Key (TGK)
	 * @param rand - (at least) 128-bit (pseudo-)random bit-string sent by the Initiator
	 * in the initial exchange.
	 * @param mscckId - used as Crypto Session Bundle ID (32-bits unsigned integer)
	 * @param csId - the Crypto Session ID (8-bits unsigned integer)
	 *
	 * @return - Master and salt SRTCP keys, MKI
	 *
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IOException - throws IOException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 */

	public SrtpKeys srtpDerivationWithMscck(byte[] mscck, byte[] rand, int mscckId,
			int csId) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		return KeyDerivationPrf.derivationMasterAndSaltKey(mscck, rand, mscckId, csId,
				mscckId);
	}

	/**
	 * SRTP/SRTCP Key Derivation for media stream protection. See specification 3GPP
	 * 33.179 version 13.4.0 (section 7.4.4-1). TGK from PCK
	 *
	 * @param pck - used as the MIKEY Traffic Generating Key (TGK)
	 * @param rand - (at least) 128-bit (pseudo-)random bit-string sent by the Initiator
	 * in the initial exchange.
	 * @param pckId - used as Crypto Session Bundle ID (32-bits unsigned integer)
	 * @param csId - the Crypto Session ID (8-bits unsigned integer)
	 *
	 * @return - Master and salt SRTP keys, MKI
	 *
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IOException - throws IOException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 */

	public SrtpKeys srtpDerivationWithPck(byte[] pck, byte[] rand, int pckId, int csId)
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		return KeyDerivationPrf.derivationMasterAndSaltKey(pck, rand, pckId, csId, pckId);
	}

	/**
	 * SRTCP Key Derivation for media stream protection. See specification 3GPP 33.179
	 * version 13.4.0 (section 9.4.5-1). TGK from KFC
	 *
	 * @param kfc - used as the MIKEY Traffic Generating Key (TGK)
	 * @param kfcRand - (at least) 128-bit (pseudo-)random bit-string sent by the
	 * Initiator in the initial exchange.
	 * @param kfcId - used as Crypto Session Bundle ID (32-bits unsigned integer)
	 *
	 * @return - Master and salt SRTP keys, MKI
	 *
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IOException - throws IOException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 */

	public SrtpKeys srtpDerivationWithKfc(byte[] kfc, byte[] kfcRand, int kfcId)
			throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		return KeyDerivationPrf.derivationMasterAndSaltKey(kfc, kfcRand, kfcId, 0, kfcId);
	}

	/**
	 * Security mechanism for media stream protection. See specification 3GPP 33.179
	 * version 13.4.0 (section 7.5.1-1).
	 *
	 * @param masterKey - SRTP Master Key
	 * @param masterSalt - SRTP Master Salt
	 *
	 * @return KeyStreamGeneratorAesGcm object from which all keystreams are generated
	 *
	 * @throws Exception - throws Exception
	 */
	public KeyStreamGeneratorAesGcm protectionOfMediaStreamSRTP(byte[] masterKey,
			byte[] masterSalt) throws Exception {
		return new KeyStreamGeneratorAesGcm(masterKey, masterSalt, SrtpProtocol.SRTP);
	}

	/**
	 * Security mechanism for floor control protection. See specification 3GPP 33.179
	 * version 13.4.0 (section 7.6.1-1).
	 *
	 * @param masterKey - SRTP Master Key
	 * @param masterSalt - SRTP Master Salt
	 *
	 * @return KeyStreamGeneratorAesGcm object from which all keystreams are generated
	 *
	 * @throws Exception - throws Exception
	 */
	public KeyStreamGeneratorAesGcm protectionOfMediaStreamSRTCP(byte[] masterKey,
			byte[] masterSalt) throws Exception {
		return new KeyStreamGeneratorAesGcm(masterKey, masterSalt, SrtpProtocol.SRTCP);
	}

	public KeyPair generateGMK(String targetMcpttId, String targetKmsMcpttId) {
		return generateKeyMaterial(targetMcpttId, targetKmsMcpttId, PurposeTag.GMK);
	}

	public KeyPair generatePCK(String targetMcpttId, String targetKmsMcpttId) {
		return generateKeyMaterial(targetMcpttId, targetKmsMcpttId, PurposeTag.PCK);
	}

	public KeyPair generateCSK(String targetMcpttId, String targetKmsMcpttId) {
		return generateKeyMaterial(targetMcpttId, targetKmsMcpttId, PurposeTag.CSK);
	}

	public KeyPair generateSPK(String targetMcpttId, String targetKmsMcpttId) {
		return generateKeyMaterial(targetMcpttId, targetKmsMcpttId, PurposeTag.SPK);
	}

	public KeyPair generateMKFC(String targetMcpttId, String targetKmsMcpttId) {
		return generateKeyMaterial(targetMcpttId, targetKmsMcpttId, PurposeTag.MKFC);
	}

	public KeyPair generateMSCCK(String targetMcpttId, String targetKmsMcpttId) {
		return generateKeyMaterial(targetMcpttId, targetKmsMcpttId, PurposeTag.MSCCK);
	}

	private KeyPair generateKeyMaterial(String targetMcpttId, String targetKmsMcpttId,
			byte purposeTag) {
		OctetString encData = new OctetString();
		OctetString key = Sakke.generateSharedSecretAndSED(encData,
				getUid(targetMcpttId.getBytes(), targetKmsMcpttId.getBytes()),
				this.domainKeys.getSakkeParameterSetIndex(),
				this.domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());

		int keyId = KeyUtils.generateKeyIdentifier(purposeTag);

		return new KeyPair(key.getOctets(), keyId);
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
	 * Encryption of xml key data. See specification 3GPP 33.179 version 13.4.0 (section
	 * 9.3.4.2 XML content encryption).
	 *
	 * @param xmlKeyData - key within xml which will be encrypted
	 * @param kek - key used for encrypting another key (KEK, key encrypting key), CSK
	 *
	 * @return Xml document with encrypted data
	 *
	 * @throws Exception - throws Exception
	 */
	public Document encryptXmlKeyData(byte[] xmlKeyData, byte[] kek) throws Exception {
		log.info("Encrypting key data...");
		return XmlEncryption.encryptXmlKeyData(xmlKeyData, kek);
	}

	/**
	 * Decryption of xml key data. See specification 3GPP 33.179 version 13.4.0 (section
	 * 9.3.4.2 XML content encryption).
	 *
	 * @param xmlKeyData - xml document with encrypted key data
	 * @param kek - key used for encrypting another key (KEK, key encrypting key), CSK
	 *
	 * @return decrypted key
	 *
	 * @throws Exception - throws Exception
	 */
	public byte[] decryptXmlKeyData(byte[] xmlKeyData, byte[] kek) throws Exception {
		log.info("Decrypting key data...");
		return XmlUtils.documentToByte(XmlEncryption.decryptXmlKeyData(xmlKeyData, kek));
	}

	/**
	 * Encryption of xml content. See specification 3GPP 33.179 version 13.4.0 (section
	 * 9.3.4.2 XML content encryption).
	 *
	 * @param xmlContent - content to be encrypted within xml
	 * @param key - key for encryption of content, CSK
	 *
	 * @return Xml document with encrypted data
	 *
	 * @throws Exception - throws Exception
	 */
	public Document encryptXmlContent(byte[] xmlContent, byte[] key) throws Exception {
		log.info("Encrypting XML content...");
		SecretKey secretKey = Aes.getSecretKey(key);
		return XmlEncryption.encryptXmlContent(xmlContent, secretKey);
	}

	/**
	 * Decryption of xml content. See specification 3GPP 33.179 version 13.4.0 (section
	 * 9.3.4.2 XML content encryption).
	 *
	 * @param xmlDoc - xml document with encrypted content
	 * @param key - key used for decryption of content, CSK
	 *
	 * @return decrypted content
	 *
	 * @throws Exception - throws Exception
	 */
	public byte[] decryptXmlContent(byte[] xmlDoc, byte[] key) throws Exception {
		log.info("Decrypting XML content...");
		SecretKey secretKey = Aes.getSecretKey(key);
		return XmlEncryption.decryptXmlContent(xmlDoc, secretKey);
	}

	/**
	 * Signing of xml for integrity protection. See specification 3GPP 33.179 version
	 * 13.4.0 (section 9.3.5 Integrity protection using XML signature (xmlsig)).
	 *
	 * @param xml - xml to be signed (MIME body in SIP request and SIP response)
	 * @param key - key for signing
	 * @param contentIdUri - Content-ID header field as specified in IETF RFC 2045
	 * containing a Content-ID ("cid") Uniform Resource Locator (URL) as specified in IETF
	 * RFC 2392.
	 *
	 * @return signed xml
	 *
	 * @throws Exception - throws Exception
	 */
	public byte[] signXml(byte[] xml, byte[] key, String contentIdUri) throws Exception {
		log.info("Signing XML...");
		SecretKey secretKey = Aes.getSecretKey(key);
		return XmlUtils.nodeToByte(XmlEncryption.signXml(xml, secretKey, contentIdUri));
	}

	/**
	 * Verification of the signature. See specification 3GPP 33.179 version 13.4.0
	 * (section 9.3.5 Integrity protection using XML signature (xmlsig)).
	 *
	 * @param xmlSignature - xml signature to be verified
	 * @param key - key for verification
	 *
	 * @return whether or not the signature is valid
	 *
	 * @throws Exception - throws Exception
	 */
	public Optional<Boolean> verifyXmlSignature(byte[] xmlSignature, byte[] key) throws Exception {
		log.info("Verifying XML...");
		SecretKey secretKey = Aes.getSecretKey(key);
		return XmlEncryption.verifyXmlSignature(xmlSignature, secretKey);
	}

	/**
	 * XML attribute encryption shall be performed by encrypting the URI and embeddeding
	 * the encrypted ciphertext within a new URI. The appended domain name of the new URI
	 * identifies the attribute as having MCPTT confidentiality protection. Encryption
	 * shall be performed using the AES-128-GCM [36], as the encryption algorithm, XPK as
	 * the key, and the use of a 96 bit randomly selected IV. See specification 3GPP
	 * 33.179 version 13.4.0 (section 9.3.4.3 XML URI attribute encryption).
	 *
	 * @param uri - URI to be encrypted
	 * @param xkp - key of encryption
	 * @param domainName - domain name
	 *
	 * @return encrypted XML URI attribute
	 *
	 * @throws NoSuchPaddingException - throws NoSuchPaddingException
	 * @throws InvalidKeyException - throws InvalidKeyException
	 * @throws NoSuchAlgorithmException - throws NoSuchAlgorithmException
	 * @throws IllegalBlockSizeException - throws IllegalBlockSizeException
	 * @throws BadPaddingException - throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException - throws
	 * InvalidAlgorithmParameterException
	 */
	public String encryptedXmlUriAttribute(String uri, byte[] xkp, String domainName)
			throws Exception {
		log.info("Encrypting XML URI...");
		SecretKey key = Aes.getSecretKey(xkp);
		return XmlEncryption.encryptXmlUriAttribute(uri, key, domainName);
	}

	/**
	 * XML attribute decryption.
	 *
	 * @param encryptedUri - encrypted XML attribute
	 * @param xkp - key for decryption
	 *
	 * @return decrypted XML attribute
	 *
	 * @throws Exception - throws Exception
	 */
	public String decryptXmlUriAttribute(String encryptedUri, byte[] xkp)
			throws Exception {
		log.info("Decrypting XML URI...");
		SecretKey key = Aes.getSecretKey(xkp);
		return XmlEncryption.decryptXmlUriAttribute(encryptedUri, key);
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
	 * Process the MIKEY-SAKKE I_MESSAGE which came from Initiator of communication
	 * according to the rules specified in Section 5.3 of [RFC3830]. Some additional
	 * processing MUST also be applied according to rules specified in Section 2.2.2 of
	 * [RFC6509].
	 *
	 * @param iMessage - MIKEY-SAKKE I_MESSAGE
	 *
	 * @return Shared Secret Value (SSV). This SSV is used as the TGK (the TEK Generation
	 * Key defined in [RFC3830]).
	 */
	public String parseMikeySakkeIMessage(MikeySakkeIMessage iMessage) {
		// todo implement ...
		return null;
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
	 * Calculate the current key period number with formula from specification 3GPP 33.179
	 * version 13.4.0 (section F.2.1 Generation of MIKEY-SAKKE UID)
	 *
	 * @return the current key period number since 0h on 1 January 1900 (e.g. 553)
	 */
	private int keyPeriod() {
		return Math.toIntExact(Math.floorDiv(
				TimeUtils.secondsFromNtpEpochTo(LocalDateTime.now())
						- this.domainKeys.getUserKeyOffset(),
				this.domainKeys.getUserKeyPeriod()));
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
