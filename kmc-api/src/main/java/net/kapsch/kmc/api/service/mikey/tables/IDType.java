package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the ID Type. See:
 * <ul>
 * <li>RFC3830 section 6.7</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class IDType {

	public static final byte NAI = 0;
	public static final byte URI = 1;

	private IDType() {
	}
}
