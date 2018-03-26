package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.Date;

import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.stream.XMLStreamException;

import com.google.common.io.ByteStreams;

import info.solidsoft.mockito.java8.api.WithBDDMockito;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.apache.commons.net.ntp.TimeStamp;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import net.kapsch.kmc.api.service.config.AppConfig;

public class ApiServiceUnitTest implements WithBDDMockito {

	public static final String BASE_URL = "/keymanagement/identity/v1";

	public static final String INITIALIZE = "/init";
	public static final String KEY_PROVISION = "/keyprov";
	public static final String CERT_CACHE = "/certcache";
	private final String mcpttId = "user@example.org";
	private HttpUrl url;
	private MockWebServer mockWebServer;
	private ApiService apiService;

	@Mock
	private AppConfig appConfigMock;

	private String getXmlData(String path) throws IOException {
		InputStream resourceAsStream = this.getClass().getResourceAsStream(path);
		byte[] data = ByteStreams.toByteArray(resourceAsStream);
		return new String(data);
	}

	private LocalDateTime getTestTime() {
		return LocalDateTime.parse("2014-02-23T09:39:14");
	}

	@Before
	public void setup() throws Exception {
		MockitoAnnotations.initMocks(this);
		this.mockWebServer = new MockWebServer();
		this.mockWebServer.start();
		this.url = this.mockWebServer.url(BASE_URL);
		this.apiService = new ApiService(
				this.url.scheme() + "://" + this.url.host() + ":" + this.url.port(),
				"test");
		when(this.appConfigMock.isTrkEnabled()).thenReturn(false);
		this.apiService.setAppConfig(this.appConfigMock);
	}

	@After
	public void tearDown() throws Exception {
		this.mockWebServer.shutdown();
	}

	@Test
	public void testInitializeRequest()
			throws IOException, InterruptedException, JAXBException, XMLStreamException {
		MockResponse response = new MockResponse();
		String body = getXmlData("/xml/KMSInitExample.xml");
		response.setBody(body);
		response.setHeader(ApiService.CONTENT_TYPE_HEADER,
				ApiService.CONTENT_TYPE_HEADER_VALUE);
		this.mockWebServer.enqueue(response);

		this.apiService.initialize();

		RecordedRequest request = this.mockWebServer.takeRequest();
		Assert.assertEquals(BASE_URL + INITIALIZE, request.getPath());
		Assert.assertEquals("POST", request.getMethod());
	}

	@Test
	public void testProvisionrequests() throws IOException, JAXBException,
			XMLStreamException, InterruptedException, DatatypeConfigurationException {
		// make response from xml
		MockResponse response = new MockResponse();
		String body = getXmlData("/xml/KMSKeyProvExample.xml");
		response.setBody(body);
		response.setHeader(ApiService.CONTENT_TYPE_HEADER,
				ApiService.CONTENT_TYPE_HEADER_VALUE);

		// test params, specific user url and specific time
		String userUri = "testUserUri";
		String ntpTime = new TimeStamp(
				Date.from(getTestTime().toInstant(ApiService.DEFAULT_TIMEZONE)))
						.toString();

		// schedule responses
		this.mockWebServer.enqueue(response);
		this.mockWebServer.enqueue(response);
		this.mockWebServer.enqueue(response);
		this.mockWebServer.enqueue(response);

		// test keyProvision request without params
		this.apiService.keyProvision(null, null);
		RecordedRequest request = this.mockWebServer.takeRequest();
		Assert.assertEquals(BASE_URL + KEY_PROVISION, request.getPath());
		Assert.assertEquals("POST", request.getMethod());

		// test keyProvision request with specific time
		this.apiService.keyProvision(this.mcpttId, getTestTime());
		request = this.mockWebServer.takeRequest();
		Assert.assertEquals(BASE_URL + KEY_PROVISION + "/" + this.mcpttId + "/"
				+ formatNtpTime(ntpTime), request.getPath());
		Assert.assertEquals("POST", request.getMethod());
	}

	@Test
	public void testCertCacheRequest()
			throws IOException, InterruptedException, JAXBException, XMLStreamException {
		MockResponse response = new MockResponse();
		String body = getXmlData("/xml/KMSKeyProvExample.xml");
		response.setBody(body);
		response.setHeader(ApiService.CONTENT_TYPE_HEADER,
				ApiService.CONTENT_TYPE_HEADER_VALUE);
		this.mockWebServer.enqueue(response);
		this.mockWebServer.enqueue(response);

		this.apiService.certCache(null);

		RecordedRequest request = this.mockWebServer.takeRequest();
		Assert.assertEquals(BASE_URL + CERT_CACHE, request.getPath());
		Assert.assertEquals("POST", request.getMethod());

		String certCache = "12345";
		this.apiService.certCache(certCache);
		request = this.mockWebServer.takeRequest();
		Assert.assertEquals(BASE_URL + CERT_CACHE + "/" + certCache, request.getPath());
		Assert.assertEquals("POST", request.getMethod());
	}

	@Test
	public void timestampTest() throws DatatypeConfigurationException {
		// test converting XMLGregorianCalendar to url param
		// String ntpTime = "d6b43232.00000000";
		String ntpTime = "D6B4404200000000";

		TimeStamp timestamp = new TimeStamp(
				Date.from(getTestTime().toInstant(ApiService.DEFAULT_TIMEZONE)));
		Assert.assertEquals(ntpTime, formatNtpTime(timestamp.toString()));
	}

	private String formatNtpTime(String ntp) {
		return ntp.replaceAll("\\.", "").toUpperCase();
	}
}
