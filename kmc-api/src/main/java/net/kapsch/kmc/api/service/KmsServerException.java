package net.kapsch.kmc.api.service;

public class KmsServerException extends RuntimeException {
	public KmsServerException(String message) {
		super(message);
	}

	public KmsServerException(String message, Throwable cause) {
		super(message, cause);
	}
}
