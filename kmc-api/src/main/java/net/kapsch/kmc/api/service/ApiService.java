package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import net.kapsch.kmc.api.service.config.AppConfig;
import net.kapsch.kms.api.DefaultMarshallerService;
import net.kapsch.kms.api.KmsResponseType;
import net.kapsch.kms.api.MarshallerService;


public class ApiService {
	private static final String TEST_3_INITIALIZE_PATH = "/home/kristina/Desktop/test3init.xml";
	private static final String TEST_3_KEY_PROVISION_PATH = "/home/kristina/Desktop/test3keyprov.xml";
	private static final String TEST_4_INITIALIZE_PATH = "/home/kristina/Desktop/test4init.xml";
	private static final String TEST_4_KEY_PROVISION_PATH = "/home/kristina/Desktop/test4keyprov.xml";
	public static final String TEST3_ACCESS_TOKEN = "eyJraWQiOiJXeGplT3lZV2pwTXZUS3lTZTJvNlRnV01vM0lhalJWWXUyR2YxaVR5ZkpZIiwiYWxnIjoiUlMyNTYifQ.eyJtY3B0dF9pZCI6InRlc3QzQGV4YW1wbGUub3JnIiwic3ViIjoiYWRtaW4iLCJhdWQiOlsiaHR0cDpcL1wvbG9jYWxob3N0OjUyMjdcL2thYXMiLCJwdHQiLCJrbSIsImNtIiwiZ20iXSwic2NwIjpbIm9wZW5pZCIsIjNncHA6bWNwdHQ6cHR0X3NlcnZlciIsIjNncHA6bWNwdHQ6a2V5X21hbmFnZW1lbnRfc2VydmVyIiwiM2dwcDptY3B0dDpjb25maWdfbWFuYWdlbWVudF9zZXJ2ZXIiLCIzZ3BwOm1jcHR0Omdyb3VwX21hbmFnZW1lbnRfc2VydmVyIl0sIm5iZiI6MTUxMTI3MTk1NywiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjUyMjdcL2thYXMiLCJleHAiOjE4MjY2MzE5NTcsImlhdCI6MTUxMTI3MTk1NywianRpIjoiMjQzMzA4ZWItNWZjNi00MWM0LWJmNDItNDNmZTNjMjM0OTBkIiwiY2lkIjoiZGUyYmNmZjItNzQxZi00NTE0LThiMDEtMDcxOTg3NjU5ZjNlIn0.Ei9sZL3PwsNCpWg8CockTE3XL50FeMk5sSthnHQHcIQvMEp16aVKcIwrlhGRtzZht3DNRIifkw6SRataPRhOdOGO4mxLZJs0jry7QQfYlmPRxc1paBqTeTjT3C-mK86j9YspdsRtmo6P4eAhr4VXnrySUemd7udRtCe_82cjNbWSLyuOVg4CwGfr8eh20nxU0wAjJShXDFj_BU6fUaLfrGg4U4wQ3aw04QHRjiQu9pwYiDe8aTXOZ4HAqrdhFAivhzl4mB7QJQICfp7Khe80pj1SZbiCRixUM8dw34iVX6zZgE8uX-0Ozg5DobpN14DGTCq_7WATVhD1tXO-djfQ4A";

	private String accessToken;

	private MarshallerService marshallerService;
	private AppConfig appConfig;

	/**
	 * ApiService constructor, sets the default parameters for connection with Kms Server.
	 *
	 * @param accessToken - Access Token
	 */
	public ApiService(String accessToken) {
		this.marshallerService = new DefaultMarshallerService();
		this.accessToken = accessToken;
		this.appConfig = new AppConfig();
	}

	// -------------------- KMS Initialize ---------------------

	/**
	 * Mock request to KMS Server for initialization of user in domain.
	 *
	 * @return KmsResponseType object which contains the KMS's own certificate (the Root
	 * KMS certificate)
	 */
	public KmsResponseType initialize() throws IOException, JAXBException, XMLStreamException {
		if (Objects.equals(this.accessToken, TEST3_ACCESS_TOKEN)) {
			String xmlString = new String(Files.readAllBytes(Paths.get(TEST_3_INITIALIZE_PATH)));
			return this.marshallerService
					.unmarshalKmsResponseType(xmlString);
		}
		else {
			String xmlString = new String(Files.readAllBytes(Paths.get(TEST_4_INITIALIZE_PATH)));
			return this.marshallerService
					.unmarshalKmsResponseType(xmlString);
		}


	}

	// -------------------- KMS KeyProvision --------------------

	/**
	 * Send the POST request to KMS Server for key provisioning for specific time.
	 *
	 * @return KmsResponseType object which contains appropriate user Key Sets
	 */
	public KmsResponseType keyProvision() throws JAXBException, XMLStreamException, IOException {
		if (Objects.equals(this.accessToken, TEST3_ACCESS_TOKEN)) {
			String xmlString = new String(Files.readAllBytes(Paths.get(TEST_3_KEY_PROVISION_PATH)));
			return this.marshallerService
					.unmarshalKmsResponseType(xmlString);
		}
		else {
			String xmlString = new String(Files.readAllBytes(Paths.get(TEST_4_KEY_PROVISION_PATH)));
			return this.marshallerService
					.unmarshalKmsResponseType(xmlString);
		}

	}
}
