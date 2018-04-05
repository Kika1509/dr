package net.kapsch.kmc.api.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Optional;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import net.kapsch.kms.api.util.XmlUtils;

public class CmdApi {

	private static final Logger log = LoggerFactory.getLogger(CmdApi.class);

	private static final String DEFAULT_KAAS_URL = "http://localhost:5227/kaas/oauth2";
	private static final String DEFAULT_KAAS_REDIRECT_URL = "http://example.com";
	private static final String DEFAULT_KMS_URL = "http://localhost:8080/kms";

	private static final String CMD_LINE_SYNTAX = "KMC";

	private static final String ARG_ACCESS_TOKEN_SHORT = "ac";
	private static final String ARG_ACCESS_TOKEN_LONG = "access-token";
	private static final String ARG_ACCESS_TOKEN_DESCRIPTION = "Access Token";

	private static final String ARG_ID_SHORT = "id";
	private static final String ARG_ID_LONG = "mcptt-id";
	private static final String ARG_ID_DESCRIPTION = "Mcptt ID";

	private static final String ARG_D_SHORT = "d";
	private static final String ARG_D_LONG = "data";
	private static final String ARG_D_DESCRIPTION = "Data for encryption (URI, key, xml content, etc.)";

	private static final String ARG_K_SHORT = "k";
	private static final String ARG_K_LONG = "key";
	private static final String ARG_K_DESCRIPTION = "Key for encryption";

	private static final String ARG_DN_SHORT = "dn";
	private static final String ARG_DN_LONG = "domain-name";
	private static final String ARG_DN_DESCRIPTION = "Domain name";

	private static final String ARG_CIDU_SHORT = "cidu";
	private static final String ARG_CIDU_LONG = "content-id-uri";
	private static final String ARG_CIDU_DESCRIPTION = "Content identifier URI";

	private static final String EXC = "encrypt-xml-content";
	private static final String EXC_ERROR = "Required " + ARG_D_SHORT + ", "
			+ ARG_K_SHORT;
	private static final String EXC_DESCRIPTION = "Encrypting XML content method ("
			+ EXC_ERROR + ")";

	private static final String DEXC = "decrypt-xml-content";
	private static final String DEXC_ERROR = "Required " + ARG_D_SHORT + ", "
			+ ARG_K_SHORT;
	private static final String DEXC_DESCRIPTION = "Decrypting XML content method ("
			+ DEXC_ERROR + ")";

	private static final String EXU = "encrypt-xml-url";
	private static final String EXU_ERROR = "Required " + ARG_D_SHORT + ", " + ARG_K_SHORT
			+ ", " + ARG_DN_SHORT;
	private static final String EXU_DESCRIPTION = "Encrypting XML URL method ("
			+ EXU_ERROR + ")";

	private static final String DEXU = "decrypt-xml-url";
	private static final String DEXU_ERROR = "Required " + ARG_D_SHORT + ", "
			+ ARG_K_SHORT;
	private static final String DEXU_DESCRIPTION = "Decrypting XML URL method ("
			+ DEXU_ERROR + ")";

	private static final String EXKD = "encrypt-xml-key-data";
	private static final String EXKD_ERROR = "Required " + ARG_D_SHORT + ", "
			+ ARG_K_SHORT;
	private static final String EXKD_DESCRIPTION = "Encrypting XML key data method ("
			+ EXKD_ERROR + ")";

	private static final String DEXKD = "decrypt-xml-key-data";
	private static final String DEXKD_ERROR = "Required " + ARG_D_SHORT + ", "
			+ ARG_K_SHORT;
	private static final String DEXKD_DESCRIPTION = "Decrypting XML key data method ("
			+ DEXKD_ERROR + ")";

	private static final String SX = "sign-xml";
	private static final String SX_ERROR = "Required " + ARG_D_SHORT + ", " + ARG_K_SHORT
			+ ", " + ARG_CIDU_SHORT;
	private static final String SX_DESCRIPTION = "Sign XML method (" + SX_ERROR + ")";

	private static final String ARG_ACTION_SHORT = "a";
	private static final String ARG_ACTION_LONG = "action";
	private static final String ARG_ACTION_DESCRIPTION = "Define which action want to use:\n"
			+ EXC + " - " + EXC_DESCRIPTION + "\n" + EXU + " - " + EXU_DESCRIPTION + "\n"
			+ EXKD + " - " + EXKD_DESCRIPTION + "\n" + SX + " - " + SX_DESCRIPTION + "\n"
			+ DEXC + " - " + DEXC_DESCRIPTION + "\n" + DEXU + " - " + DEXU_DESCRIPTION
			+ "\n" + DEXKD + " - " + DEXKD_DESCRIPTION + "\n";

	private CommandLineParser parser;
	private HelpFormatter formatter;
	private CommandLine cmd;
	private Options options;

	private Client client;

	private String kaasUrl;
	private String kaasRedirectUrl;
	private String kmsUrl;

	public CmdApi(String[] args) throws Exception {
		this.options = new Options();
		this.parser = new DefaultParser();
		this.formatter = new HelpFormatter();
		this.kaasUrl = DEFAULT_KAAS_URL;
		this.kaasRedirectUrl = DEFAULT_KAAS_REDIRECT_URL;
		this.kmsUrl = DEFAULT_KMS_URL;

		init(args);
	}

	public void init(String[] args) throws Exception {
		parseArguments(args);
	}

	public void parseArguments(String[] args) throws Exception {

		addGeneralOptions();
		addActionParams();

		try {
			this.cmd = this.parser.parse(this.options, args);
		}
		catch (ParseException e) {
			errHandler(e.getMessage());
		}

		this.client = new KmcApp().init(get(ARG_ACCESS_TOKEN_SHORT), get(ARG_ID_SHORT));

		this.client.init();

		String action = get(ARG_ACTION_SHORT);

		if (action != null) {
			switch (action) {
			case EXU:
				encryptionXmlUriAction();
				break;
			case DEXU:
				decryptionXmlUriAction();
				break;
			case EXC:
				encryptionXmlContentAction();
				break;
			case DEXC:
				decryptionXmlContentAction();
				break;
			case EXKD:
				encryptionXmlKeyDataAction();
				break;
			case DEXKD:
				decryptionXmlKeyDataAction();
				break;
			case SX:
				signXmlAction();
				break;
			default:
				errHandler("Action doesn't exist.");
			}
		}

	}

	private String get(String option) {
		return this.cmd.getOptionValue(option);
	}

	private boolean has(String option) {
		return this.cmd.hasOption(option);
	}

	/**
	 * Defining options for all action methods.
	 */
	private void addActionParams() {
		Option action = new Option(ARG_ACTION_SHORT, ARG_ACTION_LONG, true,
				ARG_ACTION_DESCRIPTION);
		action.setRequired(true);
		this.options.addOption(action);

		Option data = new Option(ARG_D_SHORT, ARG_D_LONG, true, ARG_D_DESCRIPTION);
		this.options.addOption(data);

		Option key = new Option(ARG_K_SHORT, ARG_K_LONG, true, ARG_K_DESCRIPTION);
		this.options.addOption(key);

		Option domain = new Option(ARG_DN_SHORT, ARG_DN_LONG, true, ARG_DN_DESCRIPTION);
		this.options.addOption(domain);

		Option cidu = new Option(ARG_CIDU_SHORT, ARG_CIDU_LONG, true,
				ARG_CIDU_DESCRIPTION);
		this.options.addOption(cidu);
	}

	/**
	 * General options for establishing connection with KMS and KAAS servers.
	 */
	private void addGeneralOptions() {
		Option accessToken = new Option(ARG_ACCESS_TOKEN_SHORT, ARG_ACCESS_TOKEN_LONG,
				true, ARG_ACCESS_TOKEN_DESCRIPTION);
		this.options.addOption(accessToken);

		Option mcpttId = new Option(ARG_ID_SHORT, ARG_ID_LONG, true, ARG_ID_DESCRIPTION);
		mcpttId.setRequired(true);
		this.options.addOption(mcpttId);
	}

	/**
	 * Signing of XML action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void signXmlAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT) && has(ARG_CIDU_SHORT)) {

			Path path = Paths.get(get(ARG_D_SHORT));
			byte[] data = Files.readAllBytes(path);

			byte[] signedXml = this.client.signXml(data,
					Base64.getDecoder().decode(get(ARG_K_SHORT)), get(ARG_CIDU_SHORT));

			System.out.println("Signed XMl: " + new String(signedXml));
			log.info("Signed XMl: {}", new String(signedXml));

			Optional<Boolean> validXmlSignature = this.client.verifyXmlSignature(
					signedXml, Base64.getDecoder().decode(get(ARG_K_SHORT)));

			System.out.println("Valid XML signature: " + validXmlSignature.get());
			log.info("Valid XML signature: {}", validXmlSignature.get());
		}
		else {
			errHandler(SX_ERROR + " if using " + SX);
		}
	}

	/**
	 * Encryption of XML key data action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void encryptionXmlKeyDataAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT)) {

			Document encryptXmlKeyData = this.client.encryptXmlKeyData(
					Hex.decode(get(ARG_D_SHORT)), Hex.decode(get(ARG_K_SHORT)));

			System.out.println("Encrypted XML key data: "
					+ XmlUtils.documentToString(encryptXmlKeyData));
			log.info("Encrypted XML key data: {}",
					XmlUtils.documentToString(encryptXmlKeyData));
		}
		else {
			errHandler(EXKD_ERROR + " if using " + EXKD);
		}
	}

	/**
	 * Decryption of XML key data action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void decryptionXmlKeyDataAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT)) {

			Path path = Paths.get(get(ARG_D_SHORT));
			byte[] data = Files.readAllBytes(path);
			Element dataNode = XmlUtils.bytesToDocument(data).getDocumentElement();
			Document document = XmlUtils.createRootElement("Key");
			Node keyDataNode = document.getElementsByTagName("Key").item(0);
			Node importNode = document.importNode(dataNode, true);
			keyDataNode.appendChild(importNode);

			byte[] decryptXmlKeyData = this.client.decryptXmlKeyData(
					XmlUtils.documentToByte(document), Hex.decode(get(ARG_K_SHORT)));

			Document outputDocument = XmlUtils.bytesToDocument(decryptXmlKeyData);
			Node outputNode = outputDocument.getElementsByTagName("Key").item(0);

			System.out.println("Decrypted XML key data: " + outputNode.getTextContent());
			log.info("Decrypted XML key data: {}", outputNode.getTextContent());
		}
		else {
			errHandler(DEXKD_ERROR + " if using " + DEXKD);
		}
	}

	/**
	 * Encryption of XML content action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void encryptionXmlContentAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT)) {

			Path path = Paths.get(get(ARG_D_SHORT));
			byte[] data = Files.readAllBytes(path);

			Document encryptXmlContent = this.client.encryptXmlContent(data,
					Base64.getDecoder().decode(get(ARG_K_SHORT)));

			System.out.println("Encrypted XML content: "
					+ XmlUtils.documentToString(encryptXmlContent));
			log.info("Encrypted XML content: {}",
					XmlUtils.documentToString(encryptXmlContent));
		}
		else {
			errHandler(EXC_ERROR + " if using " + EXC);
		}
	}

	/**
	 * Decryption of XML content action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void decryptionXmlContentAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT)) {

			Path path = Paths.get(get(ARG_D_SHORT));
			byte[] data = Files.readAllBytes(path);

			byte[] decryptXmlContent = this.client.decryptXmlContent(data,
					Base64.getDecoder().decode(get(ARG_K_SHORT)));

			System.out.println("Decrypted XML content: " + new String(decryptXmlContent));
			log.info("Decrypted XML content: {}", new String(decryptXmlContent));
		}
		else {
			errHandler(DEXC_ERROR + " if using " + DEXC);
		}
	}

	/**
	 * Encryption of XML URI attribute action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void encryptionXmlUriAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT) && has(ARG_DN_SHORT)) {

			String encryptedXmlUriAttribute = this.client.encryptedXmlUriAttribute(
					get(ARG_D_SHORT), Base64.getDecoder().decode(get(ARG_K_SHORT)),
					get(ARG_DN_SHORT));

			System.out.println("Encrypted XML URI: " + encryptedXmlUriAttribute);
			log.info("Encrypted XML URI: {}", encryptedXmlUriAttribute);
		}
		else {
			errHandler(EXU_ERROR + " if using " + EXU);
		}
	}

	/**
	 * Decryption of XML URI attribute action method.
	 *
	 * @throws Exception - throws Exception
	 */
	private void decryptionXmlUriAction() throws Exception {
		if (has(ARG_D_SHORT) && has(ARG_K_SHORT)) {
			String decryptXmlUriAttribute = this.client.decryptXmlUriAttribute(
					get(ARG_D_SHORT), Base64.getDecoder().decode(get(ARG_K_SHORT)));

			System.out.println("Decrypted XML URI: " + decryptXmlUriAttribute);
			log.info("Decrypted XML URI: {}", decryptXmlUriAttribute);
		}
		else {
			errHandler(DEXU_ERROR + " if using " + DEXU);
		}
	}

	/**
	 * Terminate program and print error message.
	 *
	 * @param message - error message to print
	 */
	private void errHandler(String message) {
		System.out.println(message);
		this.formatter.printHelp(CMD_LINE_SYNTAX, this.options);

		System.exit(1);
		return;
	}

	public Client getClient() {
		return this.client;
	}

}
