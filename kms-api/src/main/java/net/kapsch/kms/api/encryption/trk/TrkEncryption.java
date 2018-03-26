package net.kapsch.kms.api.encryption.trk;

import java.util.Optional;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import net.kapsch.kms.api.encryption.XmlEncryption;
import net.kapsch.kms.api.util.XmlUtils;

public class TrkEncryption {

	private final static String CIPHER = "AES";
	private final static String[] KEY_TAGS = { "UserDecryptKey", "UserSigningKeySSK",
			"UserPubTokenPVT" };

	public TrkEncryption() {
	}

	public String applyKeyProvSecurityExtension(String xml, byte[] transportKey,
			Optional<byte[]> newTransportKey, String contentIdUri) {
		TrkBuilder builder = new TrkBuilder(xml);
		for (String tag : KEY_TAGS) {
			try {
				builder.encryptKey(transportKey, tag);
			}
			catch (Exception e) {
				throw new TrkEncryptionException("Encryption of XML: " + tag + " failed");
			}
		}
		if (newTransportKey.isPresent()) {
			try {
				builder.addNewTrk(transportKey, newTransportKey.get());
			}
			catch (Exception e) {
				throw new TrkEncryptionException(
						"Adding new transport key to XML failed");
			}
		}
		builder.addSignature(transportKey, contentIdUri);

		return builder.getXml();
	}

	public String applyInitSecurityExtension(String xml, byte[] transportKey,
			Optional<byte[]> newTransportKey, String contentIdUri) {
		TrkBuilder builder = new TrkBuilder(xml);
		if (newTransportKey.isPresent()) {
			try {
				builder.addNewTrk(transportKey, newTransportKey.get());
			}
			catch (Exception e) {
				throw new TrkEncryptionException(
						"Adding new transport key to XML failed");
			}
		}
		builder.addSignature(transportKey, contentIdUri);

		return builder.getXml();
	}

	public TrkResponse resolveSecurityExtension(String xml, byte[] transportKey,
			boolean newTransportKeyPresent) {
		if (verify(xml, transportKey)) {
			byte[] newTransportKey = null;
			Document decryptedXmlDoc = null;
			try {
				decryptedXmlDoc = XmlEncryption.decryptXmlKeyData(xml.getBytes(),
						transportKey);
			}
			catch (Exception e) {
				throw new TrkEncryptionException("Decrypting XML data failed!");
			}
			if (newTransportKeyPresent) {
				Node newTransportKeyNode = decryptedXmlDoc.getDocumentElement()
						.getElementsByTagName("NewTransportKey").item(0);
				newTransportKey = Hex.decode(newTransportKeyNode.getTextContent());
				newTransportKeyNode.getParentNode().removeChild(newTransportKeyNode);
			}

			return new TrkResponse(
					XmlUtils.nodeToString(decryptedXmlDoc.getDocumentElement()
							.getElementsByTagName("KmsResponse").item(0)),
					newTransportKey);
		}
		else {
			throw new TrkEncryptionException("Verifying signature failed!");
		}
	}

	boolean verify(String xml, byte[] transportKey) {
		try {
			Node node = XmlUtils.stringToDocument(xml);
			return XmlEncryption
					.verifyXmlSignature(XmlUtils.nodeToByte(node),
							new SecretKeySpec(transportKey, CIPHER))
					.orElseThrow(() -> new Exception("Verifying signature failed!"));
		}
		catch (Exception e) {
			throw new TrkEncryptionException(e.getMessage());
		}
	}
}
