package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the CS ID map type. See:
 * <ul>
 * <li>RFC3830 section 6.1</li>
 * <li>RFC4563 section 5</li>
 * <li>RFC6043 section 6.1</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class CsIdMapType {

	public static final byte SRTP_ID = 0;
	public static final byte EMPTY_MAP = 1;
	public static final byte GENERIC_ID = 2;
	public static final byte IPSEC4_ID = 7;

	private CsIdMapType() {
	}
}
