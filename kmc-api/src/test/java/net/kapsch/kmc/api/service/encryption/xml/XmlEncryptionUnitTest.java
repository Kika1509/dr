package net.kapsch.kmc.api.service.encryption.xml;

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.apache.xml.security.utils.EncryptionConstants;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xmlunit.builder.DiffBuilder;
import org.xmlunit.diff.Diff;
import org.xmlunit.util.Nodes;

import net.kapsch.kms.api.encryption.XmlEncryption;
import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.util.XmlUtils;

public class XmlEncryptionUnitTest {

	private static boolean assertXmlEqual(String expected, String actual) {
		final Diff documentDiff = DiffBuilder.compare(expected).withTest(actual)
				.ignoreComments().ignoreWhitespace()
				.withNodeFilter(n -> !(n instanceof Element
						&& Arrays.asList(EncryptionConstants._TAG_CIPHERVALUE)
								.contains(Nodes.getQName(n).getLocalPart())))
				.build();

		return !documentDiff.hasDifferences();
	}

	@Test
	public void testSignAndVerifyXml() throws Exception {
		byte[] key = Hex.decode("06a9214036b8a15b512e03d534120006");
		SecretKey secretKey = Aes.getSecretKey(key);

		byte[] xml = ("<ExampleTag>" + "sensitive.data@example.org" + " </ExampleTag>")
				.getBytes();

		Node signedXml = XmlEncryption.signXml(xml, secretKey, "cip:mcptt1@op1.com");

		System.out.println(XmlUtils.nodeToString(signedXml));

		Optional<Boolean> valid = XmlEncryption.verifyXmlSignature(XmlUtils.nodeToByte(signedXml),
				secretKey);

		Assert.assertTrue(valid.get());
	}

	@Test
	public void testXmlUriAttributeEncryption() throws Exception {
		String xmlUriAttribute = "somebody@mcptt.org";
		String domainName = "testDomainName";
		byte[] key = Hex.decode("06a9214036b8a15b512e03d534120006");
		SecretKey secretKey = Aes.getSecretKey(key);

		// encryption
		String encryptedUri = XmlEncryption.encryptXmlUriAttribute(xmlUriAttribute,
				secretKey, domainName);

		// decryption
		String decryptedUri = XmlEncryption.decryptXmlUriAttribute(encryptedUri,
				secretKey);

		Assert.assertEquals(xmlUriAttribute, decryptedUri);
	}

	@Test
	public void testXmlKeyDataEncryption() throws Exception {
		String xml = "<Key>"
				+ "04E685A80E5FCA4FF971EF5D0CF91E05AB94196966A0546B04E64814E4C6B16C33B49BB600D044ADCD241146C0F2A19200D483071C9F8E1491EE8515513396DF93"
				+ "</Key>";
		byte[] kek = Hex.decode(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

		Document document = XmlUtils.stringToDocument(xml);
		Node keyDataNode = document.getElementsByTagName("Key").item(0);

		// encryption
		System.out.println(new String(keyDataNode.getTextContent()));
		Element encryptedXml = XmlEncryption
				.encryptXmlKeyData(Hex.decode(keyDataNode.getTextContent()), kek)
				.getDocumentElement();

		keyDataNode.setTextContent(null);
		Node importNode = document.importNode(encryptedXml, true);
		keyDataNode.appendChild(importNode);

		// decryption
		System.out.println(XmlUtils.documentToString(document));
		Document decryptedSecretKey = XmlEncryption
				.decryptXmlKeyData(XmlUtils.documentToByte(document), kek);

		Assert.assertTrue(
				assertXmlEqual(xml, XmlUtils.documentToString(decryptedSecretKey)));
	}

	@Test
	public void testContentEncryption() throws Exception {
		byte[] xmlContent = ("<test>sensitive.data@example.org</test>").getBytes();

		byte[] key = Hex.decode("000102030405060708090A0B0C0D0E0F");
		SecretKey secretKey = Aes.getSecretKey(key);

		System.out.println("\nXML:\n");
		System.out.println(new String(xmlContent));
		System.out.println();

		Document encryptedXml = XmlEncryption.encryptXmlContent(xmlContent, secretKey);

		System.out.println("\nENCRYPTED XML:\n");
		System.out.println(XmlUtils.documentToString(encryptedXml));

		byte[] decryptedXml = XmlEncryption
				.decryptXmlContent(XmlUtils.documentToByte(encryptedXml), secretKey);

		System.out.println("\nDECRYPTED XML:\n");
		System.out.println(new String(decryptedXml));
		System.out.println();

		Assert.assertEquals(new String(xmlContent), new String(decryptedXml));
		Arrays.equals(xmlContent, decryptedXml);
	}

	@Test
	public void testXmlWithContentEncryption() throws Exception {
		byte[] key = Hex.decode("000102030405060708090A0B0C0D0E0F");
		SecretKey secretKey = Aes.getSecretKey(key);

		String xml = "<ExampleTag>\n" + " sensitive.data@example.org\n"
				+ " </ExampleTag>";

		System.out.println(xml);
		// Encryption
		Document encryptedDoc = XmlEncryption
				.encryptDocument(XmlUtils.stringToDocument(xml), secretKey);
		byte[] encryptedDocBytes = XmlUtils.documentToByte(encryptedDoc);
		System.out.println(new String(encryptedDocBytes));

		// Decryption
		Document newEncryptedDoc = XmlUtils.bytesToDocument(encryptedDocBytes);

		Document decryptedDoc1 = XmlEncryption.decryptDocument(encryptedDoc, secretKey);
		Document decryptedDoc2 = XmlEncryption.decryptDocument(newEncryptedDoc,
				secretKey);
		System.out.println(XmlUtils.documentToString(decryptedDoc2));

		Assert.assertEquals(XmlUtils.documentToString(decryptedDoc1),
				XmlUtils.documentToString(decryptedDoc2));

		Assert.assertTrue(assertXmlEqual(xml, XmlUtils.documentToString(decryptedDoc1)));
	}
}
