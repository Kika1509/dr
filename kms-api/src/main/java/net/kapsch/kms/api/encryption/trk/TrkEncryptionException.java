package net.kapsch.kms.api.encryption.trk;

public class TrkEncryptionException extends RuntimeException {
	public TrkEncryptionException(String message) {
		super(message);
	}

	public TrkEncryptionException(String message, Throwable cause) {
		super(message, cause);
	}
}
