package net.kapsch.kms.api.mikeysakke.crypto;

public class EccsiException extends RuntimeException {
	public EccsiException(String message) {
		super(message);
	}

	public EccsiException(String message, Throwable cause) {
		super(message, cause);
	}
}
