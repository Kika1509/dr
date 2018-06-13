package net.kapsch.kmc.api.service.exceptions;

public class ClientException extends RuntimeException {
	public ClientException(String message) {
		super(message);
	}

	public ClientException(String message, Throwable cause) {
		super(message, cause);
	}
}
