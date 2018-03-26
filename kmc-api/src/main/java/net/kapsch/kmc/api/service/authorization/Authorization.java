package net.kapsch.kmc.api.service.authorization;

import java.io.IOException;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.kapsch.kmc.api.service.KaasAuthorizationException;
import net.kapsch.kmc.api.service.KaasServerInternalException;

/**
 * Class for communication with KAAS Server for provisioning of Access Token.
 */
public class Authorization {

	private static final Logger log = LoggerFactory.getLogger(Authorization.class);

	private static final String DEFAULT_URL = "http://localhost:5227/kaas/oauth2";
	private static final String DEFAULT_REDIRECT_URL = "http://localhost/kaas/login";
	private static final boolean DEFAULT_VERBOSE = false;

	private static final String AUTHORIZE = "/authorize";
	private static final String TOKEN = "/token";

	private String url;
	private String redirectUrl;

	private OkHttpClient client = new OkHttpClient().newBuilder().followRedirects(false)
			.build();

	private String sid;
	private String clientId;
	private AccessToken accessToken;
	private String authorizationCode;
	private String stateParameter;

	private boolean verbose;

	/**
	 * Constructor with custom params for connections to KAAS.
	 *
	 * @param sid - session id
	 * @param clientId - client id
	 * @param url - URL of KAAS
	 * @param redirectUrl - redirect URL
	 * @param verbose - print requests details
	 */
	public Authorization(String sid, String clientId, String url, String redirectUrl,
			boolean verbose) {
		this.sid = sid;
		this.clientId = clientId;
		this.url = url;
		this.redirectUrl = redirectUrl;
		this.verbose = verbose;
	}

	/**
	 * Constructor with custom params for connections to KAAS.
	 *
	 * @param sid - session id
	 * @param clientId - client id
	 * @param url - URL of KAAS
	 * @param redirectUrl - redirect URL
	 */
	public Authorization(String sid, String clientId, String url, String redirectUrl) {
		this.sid = sid;
		this.clientId = clientId;
		this.url = url;
		this.redirectUrl = redirectUrl;
		this.verbose = DEFAULT_VERBOSE;
	}

	/**
	 * Constructor with default params for connection to local KAAS.
	 *
	 * @param sid - session id
	 * @param clientId - client id
	 */
	public Authorization(String sid, String clientId) {
		this.sid = sid;
		this.clientId = clientId;
		this.url = DEFAULT_URL;
		this.redirectUrl = DEFAULT_REDIRECT_URL;
		this.verbose = DEFAULT_VERBOSE;
	}

	/**
	 * Resolve and return Access Token. If token is cached and valid just return it. If
	 * it's not cached make request to get it from KAAS and if it's cached but expired
	 * then make refresh request.
	 *
	 * @return Access Token
	 */
	public AccessToken getAccessToken() {
		if (this.accessToken != null && this.accessToken.tokenValid()) {
			log.info("Cached Token: {}, expires in: {} seconds",
					this.accessToken.getAccessToken(), this.accessToken.getExpiresIn());
			return this.accessToken;
		}
		else if (this.accessToken != null) {
			return refreshToken();
		}
		else {
			authorize();
			return token();
		}
	}

	/**
	 * Make /authorize request to KAAS to get Authorization Code for further requests.
	 */
	void authorize() {
		this.stateParameter = Util.generateStateParameter();
		HttpUrl httpUrl = HttpUrl.parse(this.url + AUTHORIZE).newBuilder()
				.addQueryParameter("response_type", "code")
				.addQueryParameter("client_id", this.clientId)
				.addQueryParameter("redirect_uri", this.redirectUrl)
				.addQueryParameter("scope",
						"openid 3gpp:mcptt:ptt_server 3gpp:mcptt:key_management_server")
				.addQueryParameter("state", this.stateParameter).build();

		Request request = new Request.Builder().url(httpUrl)
				.addHeader("Cookie", "sid=" + this.sid).build();
		if (this.verbose) {
			Util.printRequest(request, "Authorization request to KAAS");
		}
		try (Response response = this.client.newCall(request).execute()) {
			if (this.verbose) {
				Util.printResponse(response);
			}
			String stateParameterResponse = response.header("Location").split("&")[1]
					.split("=")[1];
			if (!this.stateParameter.equals(stateParameterResponse)) {
				throw new KaasAuthorizationException("State parameter not valid.");
			}

			this.authorizationCode = response.header("Location").split("&")[0]
					.split("=")[1];
			log.info("Authorization code: {}", this.authorizationCode);
		}
		catch (IOException e) {
			throw new KaasServerInternalException(e.getMessage(), e);
		}
	}

	/**
	 * Make /token request to KAAS to get Access Token.
	 *
	 * @return Access Token
	 */
	private AccessToken token() {
		HttpUrl httpUrl = HttpUrl.parse(this.url + TOKEN).newBuilder()
				.addQueryParameter("client_id", this.clientId)
				.addQueryParameter("grant_type", "authorization_code")
				.addQueryParameter("code", this.authorizationCode)
				.addQueryParameter("redirect_uri", this.redirectUrl).build();

		RequestBody body = RequestBody.create(
				MediaType.parse("application/x-www-form-urlencoded; charset=utf-8"), "");

		Request request = new Request.Builder().url(httpUrl).post(body).build();
		if (this.verbose) {
			Util.printRequest(request, "Access Token request to KAAS");
		}
		try (Response response = this.client.newCall(request).execute()) {
			String jsonData = response.body().string();
			if (this.verbose) {
				Util.printResponse(response, jsonData);
			}
			JSONObject json = new JSONObject(jsonData);

			this.accessToken = new AccessToken(json.getString("access_token"),
					json.getInt("expires_in"), json.getString("id_token"),
					json.getString("refresh_token"), json.getString("scope"),
					json.getString("token_type"), System.currentTimeMillis());
			log.info("Access Token: {}, expires in: {} seconds",
					this.accessToken.getAccessToken(), this.accessToken.getExpiresIn());
		}
		catch (JSONException | IOException e) {
			throw new KaasServerInternalException(e.getMessage(), e);
		}

		return this.accessToken;
	}

	/**
	 * Make refresh /token request to KAAS to get refreshed Access Token.
	 *
	 * @return Access Token
	 */
	private AccessToken refreshToken() {
		HttpUrl httpUrl = HttpUrl.parse(this.url + TOKEN).newBuilder()
				.addQueryParameter("client_id", this.clientId)
				.addQueryParameter("grant_type", "refresh_token")
				.addQueryParameter("refresh_token", this.accessToken.getRefreshToken())
				.build();

		RequestBody body = RequestBody.create(
				MediaType.parse("application/x-www-form-urlencoded; charset=utf-8"), "");

		Request request = new Request.Builder().url(httpUrl).post(body).build();
		if (this.verbose) {
			Util.printRequest(request, "Refresh Token request to KAAS");
		}
		try (Response response = this.client.newCall(request).execute()) {
			String jsonData = response.body().string();
			if (this.verbose) {
				Util.printResponse(response, jsonData);
			}
			JSONObject json = new JSONObject(jsonData);

			this.accessToken.setAccessToken(json.getString("access_token"));
			this.accessToken.setExpiresIn(json.getInt("expires_in"));
			this.accessToken.setScope(json.getString("scope"));
			this.accessToken.setTokenType(json.getString("token_type"));

			this.accessToken.resetTimestampStopWatch();

			log.info("Refreshed Access Token: {}, expires in: {} seconds",
					this.accessToken.getAccessToken(), this.accessToken.getExpiresIn());
		}
		catch (JSONException | IOException e) {
			throw new KaasServerInternalException(e.getMessage(), e);
		}

		return this.accessToken;
	}

	/**
	 * Get Authorization Code
	 *
	 * @return Authorization Code
	 */
	public String getAuthorizationCode() {
		return this.authorizationCode;
	}

	public String getStateParameter() {
		return this.stateParameter;
	}
}
