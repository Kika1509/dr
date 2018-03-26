package net.kapsch.kmc.api.service;

import net.kapsch.kms.api.mikeysakke.utils.OctetString;

public class UserKeyData {

	/**
	 * The ECCSI public validation token, "PVT" as defined in [9]. This is an OCTET STRING
	 * encoding of an elliptic curve point as defined in Section 2.2 of [31].
	 */
	private OctetString publicValidationToken;

	/**
	 * The SAKKE "Receiver Secret Key" as defined in [10]. This is an OCTET STRING
	 * encoding of an elliptic curve point as defined in section 2.2 of [31].
	 */
	private OctetString receiverSecretKey;

	/**
	 * The ECCSI private Key, "SSK" as defined in [9]. This is an OCTET STRING encoding of
	 * an integer as described in section 6 of [30]. Every SSK MUST be validated before
	 * being installed as a signing key. See specification RFC 6507 section 5.1.2.
	 */
	private OctetString secretSigningKey;

	/** Hashed signature. Generated during validation of SSK. Needed for signing. */
	private OctetString HS;

	public UserKeyData(OctetString publicValidationToken, OctetString receiverSecretKey,
			OctetString secretSigningKey) {
		this.publicValidationToken = publicValidationToken;
		this.receiverSecretKey = receiverSecretKey;
		this.secretSigningKey = secretSigningKey;
	}

	/**
	 * @return the public validation token
	 */
	public OctetString getPublicValidationToken() {
		return publicValidationToken;
	}

	/**
	 * sets the public validation token
	 *
	 * @param publicValidationToken - public validation token
	 */
	public void setPublicValidationToken(OctetString publicValidationToken) {
		this.publicValidationToken = publicValidationToken;
	}

	/**
	 * @return the receiver secret key
	 */
	public OctetString getReceiverSecretKey() {
		return receiverSecretKey;
	}

	/**
	 * sets the receiver secret key
	 *
	 * @param receiverSecretKey - receiver secret key
	 */
	public void setReceiverSecretKey(OctetString receiverSecretKey) {
		this.receiverSecretKey = receiverSecretKey;
	}

	/**
	 * @return the secret signing key
	 */
	public OctetString getSecretSigningKey() {
		return secretSigningKey;
	}

	/**
	 * sets the secret signing key
	 *
	 * @param secretSigningKey - secret signing key
	 */
	public void setSecretSigningKey(OctetString secretSigningKey) {
		this.secretSigningKey = secretSigningKey;
	}

	/**
	 * @return the HS
	 */
	public OctetString getHS() {
		return HS;
	}

	/**
	 * set the hs
	 *
	 * @param HS - hash
	 */
	public void setHS(OctetString HS) {
		this.HS = HS;
	}
}
