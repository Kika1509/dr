package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the Next Payload. See:
 * <ul>
 * <li>RFC3830 section 6.1</li>
 * <li>RFC6043 section 6.1</li>
 * <li>RFC6509 section 4.1</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class NextPayload {

	public static final byte LAST_PAYLOAD = 0;
	public static final byte KEMAC = 1;
	public static final byte PKE = 2;
	public static final byte DH = 3;
	public static final byte SIGN = 4;
	public static final byte T = 5;
	public static final byte ID = 6;
	public static final byte CERT = 7;
	public static final byte CHASH = 8;
	public static final byte V = 9;
	public static final byte SP = 10;
	public static final byte RAND = 11;
	public static final byte ERR = 12;
	public static final byte TR = 13;
	public static final byte IDR = 14;
	public static final byte RANR = 15;
	public static final byte TP = 16;
	public static final byte TICKET = 17;
	public static final byte KEY_DATA = 20;
	public static final byte GENERAL_EXT = 21;

	public static final byte SAKKE = 26;

	private NextPayload() {
	}
}
