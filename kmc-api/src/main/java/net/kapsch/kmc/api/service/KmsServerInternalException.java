package net.kapsch.kmc.api.service;

public class KmsServerInternalException extends RuntimeException {
	public KmsServerInternalException(String message) {
		super(message);
	}

	public KmsServerInternalException(String message, Throwable cause) {
		super(message, cause);
	}
}
