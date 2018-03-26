package net.kapsch.kms.api.encryption.aes;

final class Base64 {

	private Base64() {
	}

	static final java.util.Base64.Encoder ENCODER = java.util.Base64.getEncoder();
	static final java.util.Base64.Decoder DECODER = java.util.Base64.getDecoder();
}
