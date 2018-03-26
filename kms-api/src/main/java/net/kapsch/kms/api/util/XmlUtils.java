package net.kapsch.kms.api.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class XmlUtils {

	static {
		Init.init();
	}

	private XmlUtils() {
	}

	public static Document stringToDocument(String xmlStr) throws Exception {
		DocumentBuilderFactory builder = DocumentBuilderFactory.newInstance();
		builder.setNamespaceAware(true);
		DocumentBuilder docBuilder = builder.newDocumentBuilder();
		Document document = docBuilder.parse(new ByteArrayInputStream(xmlStr.getBytes()));

		return document;
	}

	public static Document bytesToDocument(byte[] xmlBytes) throws Exception {
		DocumentBuilderFactory builder = DocumentBuilderFactory.newInstance();
		builder.setNamespaceAware(true);
		DocumentBuilder docBuilder = builder.newDocumentBuilder();
		Document document = docBuilder.parse(new ByteArrayInputStream(xmlBytes));

		return document;
	}

	public static byte[] documentToByte(Document document) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLUtils.outputDOM(document, baos, true);
		return baos.toByteArray();
	}

	public static byte[] nodeToByte(Node node) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLUtils.outputDOM(node, baos, true);
		return baos.toByteArray();
	}

	public static Document createRootElement() throws Exception {
		return createRootElement("xml");
	}

	public static Document createRootElement(String rootTag) throws Exception {
		DocumentBuilderFactory builder = DocumentBuilderFactory.newInstance();
		builder.setNamespaceAware(true);
		DocumentBuilder docBuilder = builder.newDocumentBuilder();
		Document xmlDoc = docBuilder.newDocument();
		Element root = xmlDoc.createElement(rootTag);
		xmlDoc.appendChild(root);

		return xmlDoc;
	}

	public static String nodeToString(Node node) {
		try {
			StringWriter sw = new StringWriter();
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

			transformer.transform(new DOMSource(node), new StreamResult(sw));
			return sw.toString();
		}
		catch (Exception ex) {
			throw new RuntimeException("Error converting to String", ex);
		}
	}

	public static String documentToString(Document doc) {
		return XmlUtils.nodeToString(doc);
	}

}
