package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the Data Type. See:
 * <ul>
 * <li>RFC3830 section 6.1</li>
 * <li>RFC6509 section 4.1</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class DataType {

	public static final byte PRE_SHARED = 0;
	public static final byte PSK_VER_MSG = 1;
	public static final byte PUBLIC_KEY = 2;
	public static final byte PK_VER_MSG = 3;
	public static final byte DH_INIT = 4;
	public static final byte DH_RESP = 5;
	public static final byte ERROR = 6;

	public static final byte SAKKE = 26;

	private DataType() {
	}
}
