package net.kapsch.kms.api;

import java.security.GeneralSecurityException;

import net.kapsch.kms.api.encryption.aes.AesCbcPKCS5PaddingEncryption;
import net.kapsch.kms.api.encryption.aes.SecretKeys;

public class EncryptionService {

	public String generateKey() throws GeneralSecurityException {
		SecretKeys secretKeys = AesCbcPKCS5PaddingEncryption.generateKey();
		return ("confidentiality-key:"
				+ AesCbcPKCS5PaddingEncryption.keyString(
				secretKeys.getConfidentialityKey())
				+ "\nintegrity-key:"
				+ AesCbcPKCS5PaddingEncryption.keyString(secretKeys.getIntegrityKey()));
	}
}
