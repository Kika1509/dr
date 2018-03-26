package net.kapsch.kmc.api.service.authorization;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.json.JSONException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AuthorizationUnitTest {

	public static final String BASE_URL = "/kaas";
	public static final String AUTHORIZATION_CODE = "UDt6xa9IiaWGBmOPsK3bYHRIhr3kkK_iTcmlE16NQp8";
	public static final int EXPIRES_IN = 2;

	private MockWebServer mockWebServer;

	private Authorization authorization;

	private HttpUrl url;

	@Before
	public void setup() throws IOException, JSONException, InterruptedException {
		this.mockWebServer = new MockWebServer();
		this.mockWebServer.start();
		this.url = this.mockWebServer.url(BASE_URL);

		String url = this.url + "/oauth2";
		String redirectUrl = "http://example.com";
		String sid = "MmQwNDJlNDMtOTM4MS00Y2I1LTlhMjAtNDBmMTIwYTYxODQz";
		String clientId = "cc54401e-60f6-45e5-a5de-c35489a1e885";
		this.authorization = new Authorization(sid, clientId, url, redirectUrl);

		prepareResponses();
	}

	@After
	public void tearDown() throws IOException {
		this.mockWebServer.shutdown();
	}

	private String getStateParameter() {
		return this.authorization.getStateParameter();
	}

	private void prepareResponses() throws InterruptedException {

		final Dispatcher dispatcher = new Dispatcher() {

			@Override
			public MockResponse dispatch(RecordedRequest request)
					throws InterruptedException {

				if (request.getPath().contains(BASE_URL + "/oauth2/authorize")) {
					MockResponse response = new MockResponse();
					response.setResponseCode(302).setHeader("Location",
							"http://example.com?code=" + AUTHORIZATION_CODE + "&state="
									+ getStateParameter());
					return response;
				}
				else if (request.getPath().contains(BASE_URL + "/oauth2/token")
						&& request.getPath().contains("grant_type=authorization_code")) {
					String responseBody = "{\n"
							+ "    \"access_token\": \"eyJraWQiOiJ4bFV2SEY0QzZ0dW5rQTI1OTZnWDJHSG4yeW9HTHBvOHk1X0wwQnBRSzZRIiwiYWxnIjoiUlMyNTYifQ.eyJtY3B0dF9pZCI6InNpcDp0ZXN0MkBleGFtcGxlLm9yZyIsInN1YiI6ImFkbWluIiwiYXVkIjpbImh0dHA6XC9cL2xvY2FsaG9zdDo1MjI3XC9rYWFzIiwicHR0Iiwia20iLCJjbSIsImdtIl0sInNjcCI6WyJvcGVuaWQiLCIzZ3BwOm1jcHR0OnB0dF9zZXJ2ZXIiLCIzZ3BwOm1jcHR0OmtleV9tYW5hZ2VtZW50X3NlcnZlciIsIjNncHA6bWNwdHQ6Y29uZmlnX21hbmFnZW1lbnRfc2VydmVyIiwiM2dwcDptY3B0dDpncm91cF9tYW5hZ2VtZW50X3NlcnZlciJdLCJuYmYiOjE1MTMwMDM1MzYsImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo1MjI3XC9rYWFzIiwiZXhwIjoxNTEzMDA0MTM2LCJpYXQiOjE1MTMwMDM1MzYsImp0aSI6IjdmM2FkOWVjLTNhNjMtNDAyZS05MzQ3LWFjY2VkOWUxZjBkZSIsImNpZCI6ImNjNTQ0MDFlLTYwZjYtNDVlNS1hNWRlLWMzNTQ4OWExZTg4NSJ9.MzD1RuR8G8v1eqDZkNzjlgOM4Ztqk_U-L9x84orWkQ4f26UOrgTCLTJ-9N4QGmuvPKjzU1o59MtuYbo4HDau-zZXvoXZtnP_2-IitMxPKKKdZiyuRVcL44UxwchOJ2zFXRKt7cedYS6w63sFbmygwXwgPn8ftrAmxSJlvzN_Aus2Xt7SBscJN8OKXCo-B4LYYCaTgSR8PrfWLVpva8yteGe7POli7_rWMOjBV6PQz5twaH58Dj-yebrn-VLMuHPAZMkJk0b4HLPajOj9WXfvpOJ7zqlLauaNKN7bbE9uE-J6ZCfrpso1TKcpBnFuECNTQWrnUa2w9rGx_6ZHLP5WWw\", \n"
							+ "    \"expires_in\": " + EXPIRES_IN + ", \n"
							+ "    \"id_token\": \"eyJraWQiOiJ4bFV2SEY0QzZ0dW5rQTI1OTZnWDJHSG4yeW9HTHBvOHk1X0wwQnBRSzZRIiwiYWxnIjoiUlMyNTYifQ.eyJtY3B0dF9pZCI6InNpcDp0ZXN0MkBleGFtcGxlLm9yZyIsImF0X2hhc2giOiJvRWNkeGZFa0NfdnZoaHZpaWpjam5BIiwic3ViIjoiYWRtaW4iLCJhdWQiOiJjYzU0NDAxZS02MGY2LTQ1ZTUtYTVkZS1jMzU0ODlhMWU4ODUiLCJhY3IiOiIzZ3BwOmFjcjpwYXNzd29yZCIsImF6cCI6ImNjNTQ0MDFlLTYwZjYtNDVlNS1hNWRlLWMzNTQ4OWExZTg4NSIsImF1dGhfdGltZSI6MTUxMzAwMzQwMCwiYW1yIjpbInB3ZCJdLCJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6NTIyN1wva2FhcyIsImV4cCI6MTUxMzAwNDQzNiwiaWF0IjoxNTEzMDAzNTM2fQ.CaiHxJZQJTEF-PcgtnwyVnau5DxIFq0wT2jjJWOg7SC3saUSCwnBNYzcGqoj0T1FGFuemr-AQKRj0VqowfU9UZpZoDGQKraNi7RmYMLSBRiDSjVXCdFVseoMd540GwCu1MFil5WAlFS_4v7mjlimGNcAkS-l_OZQBF5Mv4oh9lQOwAj-WWrTZu_W1ENMOalOspHAhxw07uh_xy-O2iixocohMDNDroiovfoRqujiyse7Hzmlrniv-UzDE2WXoS_aHFoplqvq_bXcsHBXQAMgt2N8t56AzCZxyyBUKTp02RQblKa93TW-cKpwz29XGI8eFibb0Fv8FxYH9NMzSgDS_g\", \n"
							+ "    \"refresh_token\": \"z9pa15VgIaFJ6rmr_iN5We57GxhLLDzO75-esxZLDPE\", \n"
							+ "    \"scope\": \"openid 3gpp:mcptt:ptt_server 3gpp:mcptt:key_management_server 3gpp:mcptt:config_management_server 3gpp:mcptt:group_management_server\", \n"
							+ "    \"token_type\": \"Bearer\"\n" + "}";
					MockResponse response = new MockResponse();

					response.setResponseCode(200).setBody(responseBody);

					return response;
				}
				else if (request.getPath().contains(BASE_URL + "/oauth2/token")
						&& request.getPath().contains("grant_type=refresh_token")) {
					String responseBody = "{\n"
							+ "    \"access_token\": \"eyJraWQiOiJ4bFV2SEY0QzZ0dW5rQTI1OTZnWDJHSG4yeW9HTHBvOHk1X0wwQnBRSzZRIiwiYWxnIjoiUlMyNTYifQ.eyJtY3B0dF9pZCI6InNpcDp0ZXN0MkBleGFtcGxlLm9yZyIsInN1YiI6ImFkbWluIiwiYXVkIjpbImh0dHA6XC9cL2xvY2FsaG9zdDo1MjI3XC9rYWFzIiwicHR0Iiwia20iLCJjbSIsImdtIl0sInNjcCI6WyJvcGVuaWQiLCIzZ3BwOm1jcHR0OnB0dF9zZXJ2ZXIiLCIzZ3BwOm1jcHR0OmtleV9tYW5hZ2VtZW50X3NlcnZlciIsIjNncHA6bWNwdHQ6Y29uZmlnX21hbmFnZW1lbnRfc2VydmVyIiwiM2dwcDptY3B0dDpncm91cF9tYW5hZ2VtZW50X3NlcnZlciJdLCJuYmYiOjE1MTMwMDU4OTEsImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo1MjI3XC9rYWFzIiwiZXhwIjoxNTEzMDA2NDkxLCJpYXQiOjE1MTMwMDU4OTEsImp0aSI6ImQyODQ4ZjlmLTFjNGEtNGJmYS05OTdiLTY3ODgxZjAxOTE2MyIsImNpZCI6ImNjNTQ0MDFlLTYwZjYtNDVlNS1hNWRlLWMzNTQ4OWExZTg4NSJ9.hTbF4_z_9i0ApG0WPg2vHX3xpu0sYNKgVFGnN9Rw0TJh0GhSbWtDhU9LGH2ZOxYHQYANKxuD8gWwvH6JacPRIZ2kuZaT5HCqTzvhsoNPifmhdfeYzydVwCLGO0i6pK-R9d9ObzrTzl-eDfggCoCvUMQVslJvKGa3IZvyxSZWdjADSC1PeEUz53oIy2xw43JrOf3hzaDgKy2ZtKKn7eqcfCFaaS3KMi8ciSVULU5PkENry9kszSAkE4Xz1oJLYw-jokV3xrG5iPcrNlOw74DW1fS2RvhiQrH3jfWdFigihFjOCJD9-fpN6IMgNgOKV0jpcC90ajOZ3bc9yA6fo5YMOg\", \n"
							+ "    \"expires_in\": 600, \n"
							+ "    \"scope\": \"openid 3gpp:mcptt:ptt_server 3gpp:mcptt:key_management_server 3gpp:mcptt:config_management_server 3gpp:mcptt:group_management_server\", \n"
							+ "    \"token_type\": \"Bearer\"\n" + "}";
					MockResponse response = new MockResponse();

					return response.setResponseCode(200).setBody(responseBody);
				}
				return new MockResponse().setResponseCode(404);
			}
		};
		this.mockWebServer.setDispatcher(dispatcher);
	}

	@Test
	public void authorizeTest() throws Exception {

		// test
		this.authorization.authorize();

		// validate
		Assert.assertNotNull(this.authorization.getAuthorizationCode());
		Assert.assertEquals(AUTHORIZATION_CODE,
				this.authorization.getAuthorizationCode());
		Assert.assertEquals(1, this.mockWebServer.getRequestCount());
	}

	@Test
	public void getAccessTokenTest() throws Exception {

		AccessToken accessToken = this.authorization.getAccessToken();

		RecordedRequest redirectRequest = this.mockWebServer.takeRequest();
		Assert.assertNotNull(redirectRequest);
		Assert.assertEquals(2, this.mockWebServer.getRequestCount());

		Assert.assertNotNull(accessToken);
		Assert.assertNotNull(accessToken.getAccessToken());
		Assert.assertNotNull(accessToken.getRefreshToken());
		Assert.assertTrue(accessToken.getExpiresIn() > 0);
		Assert.assertNotNull(accessToken.getIdToken());
		Assert.assertNotNull(accessToken.getScope());
		Assert.assertNotNull(accessToken.getTokenType());
	}

	@Test
	public void getCachedAccessTokenTest() throws Exception {

		AccessToken accessToken = this.authorization.getAccessToken();

		AccessToken accessToken2 = this.authorization.getAccessToken();

		Assert.assertEquals(2, this.mockWebServer.getRequestCount());

		Assert.assertEquals(accessToken, accessToken2);
		Assert.assertNotNull(accessToken);
		Assert.assertNotNull(accessToken.getAccessToken());
		Assert.assertNotNull(accessToken.getRefreshToken());
		Assert.assertTrue(accessToken.getExpiresIn() > 0);
		Assert.assertNotNull(accessToken.getIdToken());
		Assert.assertNotNull(accessToken.getScope());
		Assert.assertNotNull(accessToken.getTokenType());
	}

	@Test
	public void getRefreshedAccessToken() throws Exception {

		// EXPIRES_IN variable must be less then 5 seconds
		this.authorization.getAccessToken();

		TimeUnit.SECONDS.sleep(5);

		AccessToken accessToken2 = this.authorization.getAccessToken();

		RecordedRequest redirectRequest = this.mockWebServer.takeRequest();
		Assert.assertNotNull(redirectRequest);
		Assert.assertEquals(3, this.mockWebServer.getRequestCount());

		Assert.assertNotNull(accessToken2);
		Assert.assertNotNull(accessToken2.getAccessToken());
		Assert.assertNotNull(accessToken2.getRefreshToken());
		Assert.assertTrue(accessToken2.getExpiresIn() > 0);
		Assert.assertNotNull(accessToken2.getIdToken());
		Assert.assertNotNull(accessToken2.getScope());
		Assert.assertNotNull(accessToken2.getTokenType());
	}

}
