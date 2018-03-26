package net.kapsch.kmc.api.service;

import java.io.StringReader;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import net.kapsch.kms.api.EncryptedDataType;
import net.kapsch.kms.api.KeyInfoType;

public final class MarshallerServiceXmlEncryption {
	private static final String schemaFilename = "XmlEncryption_XMLSchema.xsd";
	private static JAXBContext jaxbContext;
	private static Schema schema;
	private static XMLInputFactory xmlInputFactory;

	private MarshallerServiceXmlEncryption() {
	}

	static {
		try {
			jaxbContext = JAXBContext.newInstance(EncryptedDataType.class,
					KeyInfoType.class);
			SchemaFactory factory = SchemaFactory
					.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			schema = factory.newSchema(MarshallerServiceXmlEncryption.class
					.getClassLoader().getResource("xsd/" + schemaFilename));

			xmlInputFactory = XMLInputFactory.newInstance();
		}
		catch (Exception e) {
			// TODO handle
		}
	}

	public static EncryptedDataType unmarshalEncryptedData(String xml)
			throws XMLStreamException, JAXBException {
		XMLStreamReader reader = xmlInputFactory
				.createXMLStreamReader(new StringReader(xml));
		return unmarshaller().unmarshal(reader, EncryptedDataType.class).getValue();
	}

	private static Unmarshaller unmarshaller() throws JAXBException {
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		unmarshaller.setSchema(schema);
		return unmarshaller;
	}
}
