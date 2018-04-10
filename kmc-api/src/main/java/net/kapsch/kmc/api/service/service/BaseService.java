package net.kapsch.kmc.api.service.service;

public abstract class BaseService {

	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String BEARER_PREFIX = "Bearer ";

	public BaseService() {
	}

	public abstract String get(String path);

	public abstract String post(String xmlBody, String mediaType);

	public static String getBearerPrefix() {
		return BEARER_PREFIX;
	}

	public static String getAuthorizationHeader() {
		return AUTHORIZATION_HEADER;
	}

}
