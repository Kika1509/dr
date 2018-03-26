package net.kapsch.kms.api;

import javax.xml.bind.JAXBException;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;

/**
 * Contract responsible for governing the process of serializing specific Java content
 * trees back into XML data and vice versa. <br>
 *
 */
public interface MarshallerService {

	/**
	 * Marhsals the provided instance of {@link KmsCertificateType} to XML string.
	 *
	 * @param instance the instance to marshal.
	 * @return String (XML) representation of the provided instance.
	 * @throws JAXBException If any unexpected problem occurs during the marshaling.
	 */
	String marshal(KmsCertificateType instance) throws JAXBException;

	String marshal(KmsKeySetType instance) throws JAXBException;

	String marshal(KmsResponseType instance) throws JAXBException;

	/**
	 * Unmarshals the provided XML string to instance of {@link KmsCertificateType}
	 *
	 * @param xml the string to unmarshal.
	 * @return instance of {@link KmsCertificateType} constructed from provided XML string
	 * @throws XMLStreamException in case of well-formedness errors, as well as unexpected
	 * processing conditions.
	 * @throws FactoryConfigurationError in case an instance of {@link XMLInputFactory}
	 * cannot be loaded
	 * @throws JAXBException in case any unexpected errors occur while unmarshaling.
	 */
	KmsCertificateType unmarshalKmsCertificateType(String xml)
			throws XMLStreamException, FactoryConfigurationError, JAXBException;

	/**
	 * Unmarshals the provided XML string to instance of {@link KmsResponseType}
	 *
	 * @param xml the string to unmarshal.
	 * @return instance of {@link KmsResponseType} constructed from provided XML string
	 * @throws XMLStreamException in case of well-formedness errors, as well as unexpected
	 * processing conditions.
	 * @throws FactoryConfigurationError in case an instance of {@link XMLInputFactory}
	 * cannot be loaded
	 * @throws JAXBException in case any unexpected errors occur while unmarshaling.
	 */
	KmsResponseType unmarshalKmsResponseType(String xml)
			throws XMLStreamException, FactoryConfigurationError, JAXBException;

	/**
	 * Unmarshals the provided XML string to instance of {@link KmsKeySetType}
	 *
	 * @param xml the string to unmarshal.
	 * @return instance of {@link KmsKeySetType} constructed from provided XML string
	 * @throws XMLStreamException in case of well-formedness errors, as well as unexpected
	 * processing conditions.
	 * @throws FactoryConfigurationError in case an instance of {@link XMLInputFactory}
	 * cannot be loaded
	 * @throws JAXBException in case any unexpected errors occur while unmarshaling.
	 */
	KmsKeySetType unmarshalKmsKeySetType(String xml)
			throws XMLStreamException, FactoryConfigurationError, JAXBException;
}
