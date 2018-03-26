package net.kapsch.kms.api;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Collectors;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBException;
import javax.xml.bind.UnmarshalException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.stream.FactoryConfigurationError;
import javax.xml.stream.XMLStreamException;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.test.util.XmlExpectationsHelper;

import net.kapsch.kms.api.KmsCertificateType.KmsDomainList;
import net.kapsch.kms.api.KmsResponseType.KmsMessage;

/**
 * Test {@link DefaultMarshallerService} which provides the functionality of marshaling
 * to/from XML
 *
 */
public class DefaultMarshallerServiceUnitTest {
	private DefaultMarshallerService service;
	private KmsResponseType testKmsResponseKeyProvInstance;
	private KmsResponseType testKmsResponseInitInstance;
	private String testKmsResponseKeyProvXml;
	private String testKmsResponseInitXml;
	private static DatatypeFactory dataTypeFactory;

	static {
		try {
			dataTypeFactory = DatatypeFactory.newInstance();
		}
		catch (DatatypeConfigurationException e) {
		}
	}

	public DefaultMarshallerServiceUnitTest()
			throws DatatypeConfigurationException {
		this.service = new DefaultMarshallerService();
		this.testKmsResponseKeyProvInstance = buildTestKmsResponseKeyProvInstance();
		this.testKmsResponseInitInstance = buildTestKmsResponseInitInstance();
		this.testKmsResponseKeyProvXml = new BufferedReader(new InputStreamReader(
				this.getClass().getResourceAsStream("/xml/KMSKeyProvMarshallerExample.xml")))
						.lines().collect(Collectors.joining("\n"));
		this.testKmsResponseInitXml = new BufferedReader(new InputStreamReader(
				this.getClass().getResourceAsStream("/xml/KMSInitMarshallerExample.xml"))).lines()
						.collect(Collectors.joining("\n"));

	}

	/**
	 * test that provided test keyprov xml unmarshalls correctly to the prebuilt instance
	 *
	 * @throws JAXBException
	 * @throws XMLStreamException
	 * @throws FactoryConfigurationError
	 */
	@Test
	public void testUnmarshallKeyProv()
			throws JAXBException, XMLStreamException, FactoryConfigurationError {

		KmsResponseType actualInstance = this.service
				.unmarshalKmsResponseType(this.testKmsResponseKeyProvXml);
		Assert.assertThat(actualInstance, com.shazam.shazamcrest.matcher.Matchers
				.sameBeanAs(this.testKmsResponseKeyProvInstance));
	}

	/**
	 * test that provided test init xml unmarshalls correctly to the prebuilt instance
	 *
	 * @throws JAXBException
	 * @throws XMLStreamException
	 * @throws FactoryConfigurationError
	 */
	@Test
	public void testUnmarshallInit()
			throws JAXBException, XMLStreamException, FactoryConfigurationError {

		KmsResponseType actualInstance = this.service
				.unmarshalKmsResponseType(this.testKmsResponseInitXml);
		Assert.assertThat(actualInstance, com.shazam.shazamcrest.matcher.Matchers
				.sameBeanAs(this.testKmsResponseInitInstance));
	}

	/**
	 * test that the prebuilt keyprov instance correctly marshalls to xml
	 *
	 * @throws Exception
	 */
	@Test
	public void testMarshallKeyProv() throws Exception {

		String actualXml = this.service
				.marshal(this.testKmsResponseKeyProvInstance);
		new XmlExpectationsHelper().assertXmlEqual(this.testKmsResponseKeyProvXml,
				actualXml);
	}

	/**
	 * test that the prebuilt init instance correctly marshalls to xml
	 *
	 * @throws Exception
	 */
	@Test
	public void testMarshallInit() throws Exception {

		String actualXml = this.service
				.marshal(this.testKmsResponseInitInstance);
		new XmlExpectationsHelper().assertXmlEqual(this.testKmsResponseInitXml,
				actualXml);
	}

	/**
	 * test that invalid test xml fails in unmarshalling due to schema validation error
	 *
	 * @throws JAXBException
	 * @throws XMLStreamException
	 * @throws FactoryConfigurationError
	 */
	@Test(expected = UnmarshalException.class)
	public void testUnmarshallMalformedXml()
			throws JAXBException, XMLStreamException, FactoryConfigurationError {

		String invalidXml = this.testKmsResponseKeyProvXml.replaceAll("KmsUri", "KmsUr");
		this.service.unmarshalKmsResponseType(invalidXml);
	}

	private static KmsResponseType buildTestKmsResponseKeyProvInstance() {
		KmsKeySetType kmsKeySet1 = new KmsKeySetType();
		kmsKeySet1.setVersion("1.1.0");
		kmsKeySet1.setKmsUri("kms.example.org");
		kmsKeySet1.setCertUri("cert1.kms.example.org");
		kmsKeySet1.setIssuer("www.example.org");
		kmsKeySet1.setUserUri("user@example.org");
		kmsKeySet1.setUserID("0123456789ABCDEF0123456789ABCDEF");
		kmsKeySet1.setValidFrom(
				dataTypeFactory.newXMLGregorianCalendar("2015-12-30T00:00:00"));
		kmsKeySet1.setValidTo(
				dataTypeFactory.newXMLGregorianCalendar("2016-03-29T23:59:59"));

		kmsKeySet1.setKeyPeriodNo(BigInteger.valueOf(1514));
		kmsKeySet1.setRevoked(false);
		KeyContentType keyContentType = new KeyContentType();
		keyContentType.setValue(DatatypeConverter.parseHexBinary("DEADBEEF"));
		kmsKeySet1.setUserDecryptKey(keyContentType);
		kmsKeySet1.setUserSigningKeySSK(keyContentType);
		kmsKeySet1.setUserPubTokenPVT(keyContentType);

		KmsKeySetType kmsKeySet2 = new KmsKeySetType();
		kmsKeySet2.setVersion(kmsKeySet1.getVersion());
		kmsKeySet2.setKmsUri(kmsKeySet1.getKmsUri());
		kmsKeySet2.setCertUri(kmsKeySet1.getCertUri());
		kmsKeySet2.setIssuer(kmsKeySet1.getIssuer());
		kmsKeySet2.setUserUri("user.psuedonym@example.org");
		kmsKeySet2.setUserID("0011223344556677889900AABBCCDDEEFF");
		kmsKeySet2.setValidFrom(kmsKeySet1.getValidFrom());
		kmsKeySet2.setValidTo(kmsKeySet1.getValidTo());
		kmsKeySet2.setKeyPeriodNo(kmsKeySet1.getKeyPeriodNo());
		kmsKeySet2.setRevoked(false);
		kmsKeySet2.setUserDecryptKey(kmsKeySet1.getUserDecryptKey());
		kmsKeySet2.setUserSigningKeySSK(kmsKeySet1.getUserSigningKeySSK());
		kmsKeySet2.setUserPubTokenPVT(kmsKeySet1.getUserPubTokenPVT());

		KmsKeyProvType kmsKeyProv = new KmsKeyProvType();
		kmsKeyProv.setVersion("1.0.0");
		kmsKeyProv.getKmsKeySet().add(kmsKeySet1);
		kmsKeyProv.getKmsKeySet().add(kmsKeySet2);

		KmsMessage kmsMessage = new KmsMessage();
		kmsMessage.setKmsKeyProv(kmsKeyProv);

		return buildKmsResponseType(kmsMessage,
				"http://kms.example.org/keymanagement/identity/v1/keyprov");
	}

	private static KmsResponseType buildTestKmsResponseInitInstance() {
		KmsCertificateType kmsCertificate = new KmsCertificateType();
		kmsCertificate.setRole(RoleType.ROOT);
		kmsCertificate.setVersion("1.1.0");
		kmsCertificate.setCertUri("cert1.kms.example.org");
		kmsCertificate.setKmsUri("kms.example.org");
		kmsCertificate.setIssuer("www.example.org");
		kmsCertificate.setValidFrom(
				dataTypeFactory.newXMLGregorianCalendar("2000-01-26T00:00:00"));
		kmsCertificate.setValidTo(
				dataTypeFactory.newXMLGregorianCalendar("2025-01-26T23:59:59"));
		kmsCertificate.setRevoked(false);
		kmsCertificate.setUserIdFormat("2");
		kmsCertificate.setUserKeyOffset(BigInteger.valueOf(0));
		kmsCertificate.setUserKeyPeriod(BigInteger.valueOf(2592000));
		kmsCertificate.setPubEncKey(DatatypeConverter.parseHexBinary("029A2F"));
		kmsCertificate.setPubAuthKey(DatatypeConverter.parseHexBinary("029A2F"));
		kmsCertificate.setParameterSet(BigInteger.valueOf(1));
		kmsCertificate.setKmsDomainList(new KmsDomainList());
		kmsCertificate.getKmsDomainList().getKmsDomain()
				.addAll(Arrays.asList("sec1.example.org", "sec2.example.org"));

		KmsInitType kmsInit = new KmsInitType();
		kmsInit.setVersion("1.0.0");
		kmsInit.setKmsCertificate(kmsCertificate);

		KmsMessage kmsMessage = new KmsMessage();
		kmsMessage.setKmsInit(kmsInit);

		return buildKmsResponseType(kmsMessage,
				"http://kms.example.org/keymanagement/identity/v1/init");
	}

	private static KmsResponseType buildKmsResponseType(KmsMessage kmsMessage,
			String url) {
		KmsResponseType kmsResponseType = new KmsResponseType();
		kmsResponseType.setVersion("1.0.0");
		kmsResponseType.setKmsUri("kms.example.org");
		kmsResponseType.setUserUri("user@example.org");
		kmsResponseType
				.setTime(dataTypeFactory.newXMLGregorianCalendar("2014-01-26T10:07:14"));
		kmsResponseType.setKmsId("KMSProvider12345");
		kmsResponseType.setClientReqUrl(url);
		kmsResponseType.setKmsMessage(kmsMessage);
		return kmsResponseType;
	}

}
