package net.kapsch.kmc.api.service;

public class KaasServerInternalException extends RuntimeException {
	public KaasServerInternalException(String message) {
		super(message);
	}

	public KaasServerInternalException(String message, Throwable cause) {
		super(message, cause);
	}
}
