package net.kapsch.kms.api.encryption;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.encryption.aes.AesGcmEncryption;
import net.kapsch.kms.api.encryption.aes.AesKeyWrapWithPadding;
import net.kapsch.kms.api.mikeysakke.PurposeTag;
import net.kapsch.kms.api.util.KeyUtils;
import net.kapsch.kms.api.util.Utils;
import net.kapsch.kms.api.util.XmlUtils;

public final class XmlEncryption {

	private final static String ENCRYPTION_ALGORITHM = XMLCipher.AES_128_GCM;

	static {
		Init.init();
	}

	private XmlEncryption() {
	}

	public static String encryptXmlUriAttribute(String uri, SecretKey xkp,
			String domainName) throws Exception {

		// the encryption algorithm identifier (128-bit encryption algorithm "128-AESGCM")
		String algorithm = "128-aes-gcm";

		// 96-bit random initialisation vector (IV)
		byte[] iv = new byte[96 / 8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);

		// the base64 encoded encrypted URI
		String encryptedUri = AesGcmEncryption.encrypt(uri, xkp, iv);

		// base64 encoded encryption key identifier (XPK-ID)
		byte[] xkpId = Base64.getEncoder()
				.encode(Utils.intToBytes(KeyUtils.generateKeyIdentifier(PurposeTag.CSK)));

		StringBuilder builder = new StringBuilder();
		builder.append("sip:");
		builder.append(encryptedUri);
		builder.append(";iv=");
		builder.append(Base64.getEncoder().encodeToString(iv));
		builder.append(";key-id=");
		builder.append(new String(xkpId));
		builder.append(";alg=");
		builder.append(algorithm);
		builder.append(domainName);

		return builder.toString();
	}

	public static String decryptXmlUriAttribute(String encrytedUri, SecretKey xkp)
			throws Exception {
		String uri = encrytedUri.substring(encrytedUri.indexOf("sip:") + 4,
				encrytedUri.indexOf(";iv="));
		String iv = encrytedUri.substring(encrytedUri.indexOf(";iv=") + 4,
				encrytedUri.indexOf(";key-id="));

		return AesGcmEncryption.decrypt(uri, xkp, Base64.getDecoder().decode(iv));
	}

	public static Node signXml(byte[] xml, Key key, String contentIdUri)
			throws Exception {
		Document document = XmlUtils.createRootElement("SignedKmsResponse");
		document.getDocumentElement().setAttribute("Id", contentIdUri);

		Node importNode = document
				.importNode(XmlUtils.bytesToDocument(xml).getDocumentElement(), true);
		document.getDocumentElement().appendChild(importNode);

		DOMSignContext dsc = new DOMSignContext(key, document.getDocumentElement());
		dsc.setIdAttributeNS(document.getDocumentElement(), null, "Id");

		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

		Reference ref = factory
				.newReference("#" + contentIdUri,
						factory.newDigestMethod(DigestMethod.SHA256, null),
						Collections.singletonList(factory.newTransform(
								Transform.ENVELOPED, (TransformParameterSpec) null)),
						null, null);

		SignatureMethod signatureMethod = factory.newSignatureMethod(
				"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", null);

		SignedInfo signedInfo = factory.newSignedInfo(
				factory.newCanonicalizationMethod(
						CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null),
				signatureMethod, Collections.singletonList(ref));

		XMLSignature signature = factory.newXMLSignature(signedInfo, null);

		// sign
		signature.sign(dsc);

		return document;
	}

	public static Optional<Boolean> verifyXmlSignature(byte[] xmlSignature, Key key)
			throws Exception {
		Document xmlDoc = XmlUtils.bytesToDocument(xmlSignature);
		xmlDoc.getDocumentElement().setIdAttribute("Id", true);

		DOMValidateContext valContext = new DOMValidateContext(key,
				xmlDoc.getElementsByTagName("Signature").item(0));

		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

		XMLSignature signature = factory.unmarshalXMLSignature(valContext);

		boolean sv = signature.getSignatureValue().validate(valContext);
		System.out.println("signature validation status: " + sv);

		Iterator i = signature.getSignedInfo().getReferences().iterator();
		for (int j = 0; i.hasNext(); j++) {
			boolean refValid = ((Reference) i.next()).validate(valContext);
			System.out.println("ref[" + j + "] validity status: " + refValid);
		}

		boolean verified = signature.validate(valContext);

		if (verified) {
			return Optional.ofNullable(verified);
		}
		else {
			return Optional.empty();
		}
	}

	public static Document encryptXmlKeyData(byte[] xmlKeyData, byte[] kek)
			throws Exception {
		// generate random key which will be overwritten
		Document root = encryptXmlContent(new byte[0], Aes.generateKey(128));

		// replace <EncryptedData> element's attribute Type "Content" with "EncryptedKey"
		Node typeAttribute = root.getDocumentElement().getAttributes()
				.getNamedItem(EncryptionConstants._ATT_TYPE);
		typeAttribute.setTextContent(typeAttribute.getNodeValue().replace(
				EncryptionConstants.TYPE_CONTENT, EncryptionConstants.EncryptionSpecNS
						+ EncryptionConstants._TAG_ENCRYPTEDKEY));

		// replace <EncryptionMethod> element's attribute Algorithm "aes128-gcm" with
		// "kw-aes256"
		Node algorithmAttribute = root
				.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
						EncryptionConstants._TAG_ENCRYPTIONMETHOD)
				.item(0).getAttributes().getNamedItem(EncryptionConstants._ATT_ALGORITHM);
		algorithmAttribute.setTextContent(algorithmAttribute.getNodeValue().replace(
				EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
				EncryptionConstants.ALGO_ID_KEYWRAP_AES256));

		AesKeyWrapWithPadding aesKeyWrapWithPadding = new AesKeyWrapWithPadding();

		// wrap xml key data with kek
		byte[] wrappedKey = aesKeyWrapWithPadding.wrap(kek, xmlKeyData);

		// replace <CipherValue> element content with wrapped key
		Node cipherValueNode = root
				.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
						EncryptionConstants._TAG_CIPHERVALUE)
				.item(0);
		cipherValueNode.setTextContent(new String(Hex.encode(wrappedKey)));

		return root;
	}

	public static Document decryptXmlKeyData(byte[] xmlKeyData, byte[] kek)
			throws Exception {
		Document document = XmlUtils.bytesToDocument(xmlKeyData);

		NodeList nodeList = document.getElementsByTagNameNS(
				EncryptionConstants.EncryptionSpecNS,
				EncryptionConstants._TAG_CIPHERVALUE);

		AesKeyWrapWithPadding aesKeyWrapWithPadding = new AesKeyWrapWithPadding();

		while (nodeList.getLength() > 0) {
			Node node = nodeList.item(0);
			byte[] nodeBytes = Hex.decode(node.getTextContent());
			Node keyNode = node.getParentNode().getParentNode().getParentNode();
			byte[] newNode = Hex.encode(aesKeyWrapWithPadding.unwrap(kek, nodeBytes));
			keyNode.setTextContent(new String(newNode).toUpperCase());
		}

		return document;
	}

	public static Document encryptXmlContent(byte[] xmlContent, SecretKey secretKey)
			throws Exception {
		// create xml element and put xml content
		Document xmlDoc = XmlUtils.createRootElement();
		xmlDoc.getDocumentElement().setTextContent(new String(xmlContent));

		// encrypt xml
		Document encryptedXml = encryptDocument(xmlDoc, secretKey);

		Node node = encryptedXml.getDocumentElement().getFirstChild();
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document newDocument = builder.newDocument();
		Node importedNode = newDocument.importNode(node, true);
		newDocument.appendChild(importedNode);

		return newDocument;
	}

	public static byte[] decryptXmlContent(byte[] xmlDoc, SecretKey key)
			throws Exception {
		Document existingdoc = XmlUtils.bytesToDocument(xmlDoc);

		// create new xml element and put xml content in it
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = dbf.newDocumentBuilder();
		Document doc = builder.newDocument();
		Element root = doc.createElement("xml");
		doc.appendChild(root);
		Node copy = doc.importNode(existingdoc.getDocumentElement(), true);
		root.appendChild(copy);
		Document newDoc = XmlUtils.stringToDocument(XmlUtils.nodeToString(root));

		Document decryptedXml = decryptDocument(newDoc, key);

		return decryptedXml.getDocumentElement().getTextContent().trim().getBytes();
	}

	public static Document encryptDocument(Document document, SecretKey secretKey)
			throws Exception {

		// Initialize the cipher for encrypting the data
		XMLCipher keyCipher = XMLCipher.getInstance(ENCRYPTION_ALGORITHM);
		keyCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

		// Setting keyinfo inside the encrypted data being prepared
		EncryptedData encryptedData = keyCipher.getEncryptedData();

		Element rootElement = document.getDocumentElement();

		// Do the actual encryption. "true" below indicates that we want to encrypt only
		// it's content and not the complete element.
		keyCipher.doFinal(document, rootElement, true);

		return document;
	}

	public static Document decryptDocument(Document document, SecretKey key)
			throws Exception {
		// Find the encrypted data element: Yet another method. Will retrieve the first
		// encrypted element by its tag
		Element encryptedDataElement = (Element) document
				.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
						EncryptionConstants._TAG_ENCRYPTEDDATA)
				.item(0);

		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, key);

		// The following doFinal call replaces the encrypted data with decrypted contents
		// in the document
		xmlCipher.doFinal(document, encryptedDataElement);

		return document;
	}
}
