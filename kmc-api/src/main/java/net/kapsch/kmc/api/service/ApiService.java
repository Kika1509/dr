package net.kapsch.kmc.api.service;

import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import net.kapsch.kmc.api.service.config.AppConfig;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;


import net.kapsch.kms.api.DefaultMarshallerService;
import net.kapsch.kms.api.KmsCertCacheType;
import net.kapsch.kms.api.KmsInitType;
import net.kapsch.kms.api.KmsKeyProvType;
import net.kapsch.kms.api.KmsResponseType;
import net.kapsch.kms.api.MarshallerService;
import org.apache.commons.net.ntp.TimeStamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ApiService {

	public final static ZoneOffset DEFAULT_TIMEZONE = ZoneOffset.ofHours(0);
	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String BEARER_PREFIX = "Bearer ";
	static final String CONTENT_TYPE_HEADER = "Content-Type";
	static final String CONTENT_TYPE_HEADER_VALUE = "text/xml";
	private final static LocalDateTime MINIMAL_DATE = LocalDateTime.of(1900, 1, 1, 0, 0);
	private static final Logger log = LoggerFactory.getLogger(ApiService.class);
	private static final String BASE_URL = "/keymanagement/identity/v1";
	private static final String INITIALIZE = "/init";
	private static final String KEY_PROVISION = "/keyprov";
	private static final String CERT_CACHE = "/certcache";
	/** KMS Server URL (schema + address + port) */
	private final String kmsUrl;
	private String accessToken;

	private OkHttpClient client;
	private MarshallerService marshallerService;
	private AppConfig appConfig;

	// cached results
	private Optional<KmsResponseType> lastInitResponseCached = Optional.empty();
	private Optional<KmsResponseType> lastKeyProvResponseCached = Optional.empty();

	private Optional<byte[]> newTransportKey = Optional.empty();

	/**
	 * ApiService constructor, sets the default parameters for connection with Kms Server.
	 *
	 * @param kmsUrl - kms server url
	 * @param accessToken - Access Token
	 */
	public ApiService(String kmsUrl, String accessToken) {
		this.marshallerService = new DefaultMarshallerService();
		this.client = new OkHttpClient.Builder().connectTimeout(30, TimeUnit.SECONDS)
				.readTimeout(30, TimeUnit.SECONDS).build();
		this.kmsUrl = kmsUrl;
		this.accessToken = BEARER_PREFIX + accessToken;
		this.appConfig = new AppConfig();
	}

	/**
	 * Build url from default parameters and specific path.
	 *
	 * @param path - specific path
	 *
	 * @return String url
	 */
	private String buildUrl(String path) {
		return this.kmsUrl + BASE_URL + path;
	}

	/**
	 * Remove dot from string and make uppercase
	 *
	 * @param ntp - time to format
	 *
	 * @return formatted string
	 */
	private String formatNtpTime(String ntp) {
		return ntp.replaceAll("\\.", "").toUpperCase();
	}

	// -------------------- KMS Initialize ---------------------

	/**
	 * Send the POST request to KMS Server for initialization of user in domain.
	 *
	 * @return KmsResponseType object which contains the KMS's own certificate (the Root
	 * KMS certificate)
	 *
	 */
	public KmsResponseType initialize() {
		RequestBody body = RequestBody.create(null, new byte[0]);
		Request request = new Request.Builder().url(buildUrl(INITIALIZE))
				.header(AUTHORIZATION_HEADER, this.accessToken).post(body).build();
		try (Response response = this.client.newCall(request).execute()) {
			if (!response.isSuccessful()) {
				if (response.code() == 500) {
					throw new KmsServerInternalException("Response code: "
							+ response.code() + " (" + response.message() + ")");
				}
				else if (response.code() == 401) {
					throw new KaasAuthorizationException("Access Token expired");
				}
				else {
					throw new KmsServerException("Response code: " + response.code()
							+ " (" + response.message() + ")");
				}
			}
			final String contentType = response.header(CONTENT_TYPE_HEADER);
			if (contentType != null && !contentType.contains(CONTENT_TYPE_HEADER_VALUE)) {
				throw new KmsServerException("Wrong content type " + contentType);
			}
			String res = response.body().string();
			log.info("/init response: {}", res);
			KmsResponseType kmsResponseType = this.marshallerService
					.unmarshalKmsResponseType(res);
			this.lastInitResponseCached = Optional.ofNullable(kmsResponseType);
			return kmsResponseType;
		}
		catch (KmsServerInternalException | KmsServerException
				| KaasAuthorizationException e) {
			throw e;
		}
		catch (Exception e) {
			throw new KmsServerInternalException(e.getMessage(), e);
		}
	}

	// -------------------- KMS KeyProvision --------------------

	/**
	 * Send the POST request to KMS Server for key provisioning for specific time.
	 *
	 * @param time - specific time which the client would like the KMS to provision
	 *
	 * @return KmsResponseType object which contains appropriate user Key Sets
	 */
	public KmsResponseType keyProvision(String mcpttId, LocalDateTime time) {
		StringBuilder path = new StringBuilder();
		if (mcpttId != null) {
			path.append("/").append(mcpttId);
		}
		if (time != null) {
			if (mcpttId == null) {
				throw new IllegalArgumentException(
						"Missing mcpttId for case there is defined time");
			}
			if (time.isBefore(MINIMAL_DATE)) {
				throw new IllegalArgumentException("Date is before 1900-01-01");
			}
			TimeStamp timestamp = new TimeStamp(
					Date.from(time.toInstant(DEFAULT_TIMEZONE)));
			path.append("/").append(formatNtpTime(timestamp.toString()));
		}

		return keyProvisionWithPath(path.toString());
	}

	/**
	 * Send the POST request to KMS Server for key provisioning for specific time.
	 *
	 * @param path - url path you want to append to request
	 *
	 * @return KmsResponseType object which contains appropriate user Key Sets
	 */
	public KmsResponseType keyProvisionWithPath(String path) {
		StringBuilder url = new StringBuilder(buildUrl(KEY_PROVISION)).append(path);

		RequestBody body = RequestBody.create(null, new byte[0]);
		Request request = new Request.Builder().url(url.toString())
				.header(AUTHORIZATION_HEADER, this.accessToken).post(body).build();
		try (Response response = this.client.newCall(request).execute()) {
			if (!response.isSuccessful()) {
				if (response.code() == 500) {
					throw new KmsServerInternalException("Response code: "
							+ response.code() + " (" + response.message() + ")");
				}
				else if (response.code() == 401) {
					throw new KaasAuthorizationException("Access Token expired");
				}
				else {
					throw new KmsServerException("Response code: " + response.code()
							+ " (" + response.message() + ")");
				}
			}
			final String contentType = response.header(CONTENT_TYPE_HEADER);
			if (contentType != null && !contentType.contains(CONTENT_TYPE_HEADER_VALUE)) {
				throw new KmsServerException("Wrong content type " + contentType);
			}
			String res = response.body().string();
			log.info("/keyprov response: {}", res);
			KmsResponseType kmsResponseType = this.marshallerService
					.unmarshalKmsResponseType(res);
			this.lastKeyProvResponseCached = Optional.ofNullable(kmsResponseType);
			return kmsResponseType;
		}
		catch (KmsServerInternalException | KmsServerException
				| KaasAuthorizationException e) {
			throw e;
		}
		catch (Exception e) {
			throw new KmsServerInternalException(e.getMessage(), e);
		}
	}

	// -------------------- KMS CertCache --------------------

	/**
	 * Send the POST request to KMS Server for cache certificates.
	 *
	 * @param latestVersion - latestVersion is number of client’s latest version
	 *
	 * @return KmsResponseType object which contains cache of KMS certificates allowing
	 * inter-domain communications
	 *
	 */
	public KmsResponseType certCache(String latestVersion) {
		StringBuilder url = new StringBuilder(buildUrl(CERT_CACHE));
		if (latestVersion != null) {
			url.append("/" + latestVersion);
		}

		RequestBody body = RequestBody.create(null, new byte[0]);
		Request request = new Request.Builder().url(url.toString())
				.header(AUTHORIZATION_HEADER, this.accessToken).post(body).build();
		try (Response response = this.client.newCall(request).execute()) {
			if (!response.isSuccessful()) {
				if (response.code() == 500) {
					throw new KmsServerInternalException("Response code: "
							+ response.code() + " (" + response.message() + ")");
				}
				else if (response.code() == 401) {
					throw new KaasAuthorizationException("Access Token expired");
				}
				else {
					throw new KmsServerException("Response code: " + response.code()
							+ " (" + response.message() + ")");
				}
			}
			final String contentType = response.header(CONTENT_TYPE_HEADER);
			if (contentType != null && !contentType.contains(CONTENT_TYPE_HEADER_VALUE)) {
				throw new KmsServerException("Wrong content type " + contentType);
			}
			return this.marshallerService
					.unmarshalKmsResponseType(response.body().string());
		}
		catch (KmsServerInternalException | KmsServerException
				| KaasAuthorizationException e) {
			throw e;
		}
		catch (Exception e) {
			throw new KmsServerInternalException(e.getMessage(), e);
		}
	}

	public KmsCertCacheType certCacheExtracted(String latestVersion) {
		return this.certCache(latestVersion).getKmsMessage().getKmsCertCache();
	}

	public Optional<KmsResponseType> getLastInitResponseCached() {
		return this.lastInitResponseCached;
	}

	public Optional<KmsInitType> getLastInitExtractedCached() {
		return this.lastInitResponseCached
				.map(kmsResponseType -> kmsResponseType.getKmsMessage().getKmsInit());
	}

	public Optional<KmsResponseType> getLastKeyProvResponseCached() {
		return this.lastKeyProvResponseCached;
	}

	public Optional<KmsKeyProvType> getLastKeyProvExtractedCached() {
		return this.lastKeyProvResponseCached
				.map(kmsResponseType -> kmsResponseType.getKmsMessage().getKmsKeyProv());
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = BEARER_PREFIX + accessToken;
	}

	public void setAppConfig(AppConfig appConfig) {
		this.appConfig = appConfig;
	}

	public Optional<byte[]> getNewTransportKey() {
		return this.newTransportKey;
	}

	public AppConfig getAppConfig() {
		return this.appConfig;
	}
}
