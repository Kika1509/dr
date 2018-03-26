package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the PRF Func. See:
 * <ul>
 * <li>RFC3830 section 6.1</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class PRFFunc {

	public static final byte MIKEY_1 = 0;
	public static final byte PRF_HMAC_SHA_256 = 1;

	private PRFFunc() {
	}
}
