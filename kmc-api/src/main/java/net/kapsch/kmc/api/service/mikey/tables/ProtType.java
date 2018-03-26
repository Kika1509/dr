package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the Prot type. See:
 * <ul>
 * <li>RFC3830 section 6.10</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class ProtType {

	public static final byte SRTP = 0;

	private ProtType() {
	}
}
