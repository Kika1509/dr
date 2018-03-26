package net.kapsch.kms.api;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

public class DefaultMarshallerService implements MarshallerService {
	private static final String schemaFilename = "KmsInterface_XMLSchema.xsd";
	private static final String schemaFilenameUrl = "http://www.kapsch.net/mcptt/xml/KmsInterface";
	private static JAXBContext jaxbContext;
	private static Schema schema;
	private static XMLInputFactory xmlInputFactory;

	static {
		try {
			jaxbContext = JAXBContext.newInstance(KmsResponseType.class,
					KmsCertificateType.class, KmsKeySetType.class);
			SchemaFactory factory = SchemaFactory
					.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			schema = factory.newSchema(DefaultMarshallerService.class.getClassLoader()
					.getResource("xsd/" + schemaFilename));

			xmlInputFactory = XMLInputFactory.newInstance();
		}
		catch (Exception e) {
			// TODO handle
		}
	}

	private static Marshaller marshaller() throws JAXBException, PropertyException {
		Marshaller marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty("jaxb.formatted.output", false);
		marshaller.setProperty("jaxb.schemaLocation",
				schemaFilenameUrl + " " + schemaFilename);
		return marshaller;
	}

	private static Unmarshaller unmarshaller() throws JAXBException {
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		unmarshaller.setSchema(schema);
		return unmarshaller;
	}

	@Override
	public String marshal(KmsResponseType instance) throws JAXBException {
		StringWriter stringWriter = new StringWriter();
		marshaller().marshal(new ObjectFactory().createKmsResponse(instance),
				stringWriter);
		return stringWriter.toString();
	}

	@Override
	public String marshal(KmsCertificateType instance) throws JAXBException {
		StringWriter stringWriter = new StringWriter();
		marshaller().marshal(new ObjectFactory().createKmsCertificate(instance),
				stringWriter);
		return stringWriter.toString();
	}

	@Override
	public String marshal(KmsKeySetType instance) throws JAXBException {
		StringWriter stringWriter = new StringWriter();
		marshaller().marshal(new ObjectFactory().createKmsKeySet(instance), stringWriter);
		return stringWriter.toString();
	}

	@Override
	public KmsCertificateType unmarshalKmsCertificateType(String xml)
			throws XMLStreamException, FactoryConfigurationError, JAXBException {
		XMLStreamReader reader = xmlInputFactory
				.createXMLStreamReader(new StringReader(xml));
		return unmarshaller().unmarshal(reader, KmsCertificateType.class).getValue();
	}

	@Override
	public KmsResponseType unmarshalKmsResponseType(String xml)
			throws XMLStreamException, FactoryConfigurationError, JAXBException {
		XMLStreamReader reader = xmlInputFactory
				.createXMLStreamReader(new StringReader(xml));
		return unmarshaller().unmarshal(reader, KmsResponseType.class).getValue();
	}

	@Override
	public KmsKeySetType unmarshalKmsKeySetType(String xml)
			throws XMLStreamException, FactoryConfigurationError, JAXBException {
		XMLStreamReader reader = xmlInputFactory
				.createXMLStreamReader(new StringReader(xml));
		return unmarshaller().unmarshal(reader, KmsKeySetType.class).getValue();
	}
}
