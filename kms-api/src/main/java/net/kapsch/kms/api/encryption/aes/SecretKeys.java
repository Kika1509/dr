package net.kapsch.kms.api.encryption.aes;

import javax.crypto.SecretKey;

/**
 * Holder class that has both the secret AES key for encryption (confidentiality) and the
 * secret HMAC key for integrity.
 */

public class SecretKeys {

	private SecretKey confidentialityKey;
	private SecretKey integrityKey;

	/**
	 * Construct the secret keys container.
	 * @param confidentialityKeyIn The AES key
	 * @param integrityKeyIn the HMAC key
	 */
	public SecretKeys(SecretKey confidentialityKeyIn, SecretKey integrityKeyIn) {
		setConfidentialityKey(confidentialityKeyIn);
		setIntegrityKey(integrityKeyIn);
	}

	public SecretKey getConfidentialityKey() {
		return this.confidentialityKey;
	}

	public void setConfidentialityKey(SecretKey confidentialityKey) {
		this.confidentialityKey = confidentialityKey;
	}

	public SecretKey getIntegrityKey() {
		return this.integrityKey;
	}

	public void setIntegrityKey(SecretKey integrityKey) {
		this.integrityKey = integrityKey;
	}

	/**
	 * Encodes the two keys as a string
	 * @return base64(confidentialityKey):base64(integrityKey)
	 */
	@Override
	public String toString() {
		return Base64.ENCODER.encodeToString(getConfidentialityKey().getEncoded()) + ":"
				+ Base64.ENCODER.encodeToString(getIntegrityKey().getEncoded());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + this.confidentialityKey.hashCode();
		result = prime * result + this.integrityKey.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SecretKeys other = (SecretKeys) obj;
		if (!this.integrityKey.equals(other.integrityKey)) {
			return false;
		}
		if (!this.confidentialityKey.equals(other.confidentialityKey)) {
			return false;
		}
		return true;
	}
}
