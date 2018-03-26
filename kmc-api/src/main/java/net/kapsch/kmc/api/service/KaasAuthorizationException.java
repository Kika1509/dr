package net.kapsch.kmc.api.service;

public class KaasAuthorizationException extends RuntimeException {
	public KaasAuthorizationException(String message) {
		super(message);
	}

	public KaasAuthorizationException(String message, Throwable cause) {
		super(message, cause);
	}
}
