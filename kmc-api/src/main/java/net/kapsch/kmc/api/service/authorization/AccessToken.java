package net.kapsch.kmc.api.service.authorization;

/**
 * Class which contains Access Token and his attributes provisioned from KAAS.
 */
public class AccessToken {

	private String accessToken;
	private int expiresIn;
	private String idToken;
	private String refreshToken;
	private String scope;
	private String tokenType;

	private long accessTokenTimestampStopWatch;

	public AccessToken(String accessToken, int expiresIn, String idToken,
			String refreshToken, String scope, String tokenType,
			long accessTokenTimestampStopWatch) {
		this.accessToken = accessToken;
		this.expiresIn = expiresIn;
		this.idToken = idToken;
		this.refreshToken = refreshToken;
		this.scope = scope;
		this.tokenType = tokenType;
		this.accessTokenTimestampStopWatch = accessTokenTimestampStopWatch;
	}

	/**
	 * Get access token.
	 *
	 * @return access token
	 */
	public String getAccessToken() {
		return this.accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	/**
	 * Get period after which access token will be expired.
	 *
	 * @return expiration period in seconds
	 */
	public int getExpiresIn() {
		return this.expiresIn;
	}

	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}

	/**
	 * Get period after which access token will be expired.
	 *
	 * @return expiration period in milliseconds
	 */
	public int getExpiresInMilis() {
		return this.expiresIn * 1000;
	}

	/**
	 * Get id token.
	 *
	 * @return id token
	 */
	public String getIdToken() {
		return this.idToken;
	}

	/**
	 * Get refresh token.
	 *
	 * @return refresh token
	 */
	public String getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * Get scope.
	 *
	 * @return scope
	 */
	public String getScope() {
		return this.scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	/**
	 * Get token type.
	 *
	 * @return token type
	 */
	public String getTokenType() {
		return this.tokenType;
	}

	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}

	/**
	 * Resets the timestamp stop watch to current timestamp.
	 */
	public void resetTimestampStopWatch() {
		this.accessTokenTimestampStopWatch = System.currentTimeMillis();
	}

	/**
	 * Validate token. Check if token is expired.
	 *
	 * @return if token is valid or not
	 */
	boolean tokenValid() {
		long passedTime = System.currentTimeMillis() - this.accessTokenTimestampStopWatch;
		if (this.accessTokenTimestampStopWatch != 0) {
			if (passedTime >= this.getExpiresInMilis()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		return "AccessToken{" + "accessToken='" + accessToken + '\'' + ", expiresIn="
				+ expiresIn + ", idToken='" + idToken + '\'' + ", refreshToken='"
				+ refreshToken + '\'' + ", scope='" + scope + '\'' + ", tokenType='"
				+ tokenType + '\'' + ", accessTokenTimestampStopWatch="
				+ accessTokenTimestampStopWatch + '}';
	}
}
