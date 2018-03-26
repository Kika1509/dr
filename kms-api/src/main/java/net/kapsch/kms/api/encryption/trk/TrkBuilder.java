package net.kapsch.kms.api.encryption.trk;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import net.kapsch.kms.api.encryption.XmlEncryption;
import net.kapsch.kms.api.util.XmlUtils;

public class TrkBuilder {

	private final static String CIPHER = "AES";
	private final static String NEW_TRANSPORT_KEY_TAG = "NewTransportKey";
	private final static String KMS_INIT_TAG = "KmsInit";
	private final static String KMS_KEY_PROV_TAG = "KmsKeyProv";

	private String xml;

	public TrkBuilder(String xml) {
		this.xml = xml;
	}

	public void addSignature(byte[] key, String contentIdUri) {
		try {
			this.xml = new String(XmlUtils.nodeToByte(XmlEncryption.signXml(
					this.xml.getBytes(), new SecretKeySpec(key, CIPHER), contentIdUri)));
		}
		catch (Exception e) {
			throw new TrkEncryptionException(e.getMessage(), e);
		}
	}

	public void encryptKey(byte[] key, String keyTag) throws Exception {
		Document document = XmlUtils.stringToDocument(this.xml);
		Node keyNode = document.getElementsByTagName(keyTag).item(0);
		if (keyNode == null) {
			throw new TrkEncryptionException("Element " + keyTag + " doesn't exist.");
		}
		String keyData = keyNode.getTextContent();
		Document encryptedDoc = XmlEncryption.encryptXmlKeyData(Hex.decode(keyData), key);
		Node encryptedImportedNode = document
				.importNode(encryptedDoc.getDocumentElement(), true);
		keyNode.setTextContent(null);
		keyNode.appendChild(encryptedImportedNode);

		this.xml = XmlUtils.documentToString(document);
	}

	public void addNewTrk(byte[] key, byte[] newKey) throws Exception {
		Document newTransportKeyDocument = XmlUtils
				.createRootElement(NEW_TRANSPORT_KEY_TAG);
		newTransportKeyDocument.getDocumentElement()
				.setTextContent(new String(Hex.encode(newKey)));

		Document document = XmlUtils.stringToDocument(this.xml);
		Node node = (document.getElementsByTagName(KMS_INIT_TAG).item(0) != null)
				? document.getElementsByTagName(KMS_INIT_TAG).item(0)
				: document.getElementsByTagName(KMS_KEY_PROV_TAG).item(0);
		Node newTransportKeyNode = document
				.importNode(newTransportKeyDocument.getDocumentElement(), true);
		node.appendChild(newTransportKeyNode);

		this.xml = XmlUtils.documentToString(document);

		encryptKey(key, NEW_TRANSPORT_KEY_TAG);
	}

	public String getXml() {
		return this.xml;
	}
}
