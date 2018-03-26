package net.kapsch.kms.api.mikeysakke.crypto;

public class SakkeException extends RuntimeException {
	public SakkeException(String message) {
		super(message);
	}

	public SakkeException(String message, Throwable cause) {
		super(message, cause);
	}
}
