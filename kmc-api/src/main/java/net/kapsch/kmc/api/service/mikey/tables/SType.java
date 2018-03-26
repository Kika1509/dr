package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the S type. See:
 * <ul>
 * <li>RFC3830 section 6.5</li>
 * <li>RFC6509 section 4.3</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class SType {

	public static final byte RSA_PKCS = 0;
	public static final byte RSA_PSS = 1;
	public static final byte ECCSI = 2;

	private SType() {
	}
}
