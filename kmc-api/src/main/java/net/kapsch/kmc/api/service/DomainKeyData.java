package net.kapsch.kmc.api.service;

import net.kapsch.kms.api.mikeysakke.utils.OctetString;

public class DomainKeyData {

	private static final int SAKKE_PARAM_SET_INDEX_DEFAULT = 1;

	/**
	 * The ECCSI Public Key (KPAK in IETF RFC 6507 [9]). This is an OCTET STRING encoding
	 * of an elliptic curve point.
	 */
	private OctetString publicAuthenticationKey;

	/**
	 * The SAKKE Public Key (Z_T in IETF RFC 6508 [10]). This is an OCTET STRING encoding
	 * of an elliptic curve point.
	 */
	private OctetString kmsPublicKey;

	/** The choice of parameter set used for SAKKE and ECCSI (should be 1). */
	private int sakkeParameterSetIndex;

	/**
	 * The number of seconds that each user key issued by this KMS should be used (e.g.
	 * '2419200').
	 */
	private int userKeyPeriod;

	/**
	 * The offset in seconds from 0h on 1st Jan 1900 that the segmentation of key periods
	 * starts (e.g. '0').
	 */
	private int userKeyOffset;

	/**
	 * DomainKeyData constructor, sets the keys values.
	 *
	 * @param pubAuthKey - KMS Public Authentication key
	 * @param pubEncKey - KMS Public key
	 * @param userKeyPeriod - User Key Period
	 * @param userKeyOffset - User Key Offset
	 */
	public DomainKeyData(OctetString pubAuthKey, OctetString pubEncKey, int userKeyPeriod,
			int userKeyOffset) {
		this.publicAuthenticationKey = pubAuthKey;
		this.kmsPublicKey = pubEncKey;
		this.sakkeParameterSetIndex = SAKKE_PARAM_SET_INDEX_DEFAULT;
		this.userKeyPeriod = userKeyPeriod;
		this.userKeyOffset = userKeyOffset;
	}

	public OctetString getPublicAuthenticationKey() {
		return publicAuthenticationKey;
	}

	public void setPublicAuthenticationKey(OctetString publicAuthenticationKey) {
		this.publicAuthenticationKey = publicAuthenticationKey;
	}

	public OctetString getKmsPublicKey() {
		return kmsPublicKey;
	}

	public void setKmsPublicKey(OctetString kmsPublicKey) {
		this.kmsPublicKey = kmsPublicKey;
	}

	public int getSakkeParameterSetIndex() {
		return sakkeParameterSetIndex;
	}

	public void setSakkeParameterSetIndex(int sakkeParameterSetIndex) {
		this.sakkeParameterSetIndex = sakkeParameterSetIndex;
	}

	public int getUserKeyPeriod() {
		return this.userKeyPeriod;
	}

	public void setUserKeyPeriod(int userKeyPeriod) {
		this.userKeyPeriod = userKeyPeriod;
	}

	public int getUserKeyOffset() {
		return this.userKeyOffset;
	}

	public void setUserKeyOffset(int userKeyOffset) {
		this.userKeyOffset = userKeyOffset;
	}
}
