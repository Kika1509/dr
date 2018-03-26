package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the TS type. See:
 * <ul>
 * <li>RFC3830 section 6.6</li>
 * <li>RFC6043 section 6.3</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class TSType {

	public static final byte NTP_UTC = 0;
	public static final byte NTP = 1;
	public static final byte COUNTER = 2;
	public static final byte NTP_UTC_32 = 3;

	private TSType() {
	}
}
