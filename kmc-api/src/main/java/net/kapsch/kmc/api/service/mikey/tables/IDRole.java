package net.kapsch.kmc.api.service.mikey.tables;

/**
 * Defines possible values for the ID Role. See:
 * <ul>
 * <li>RFC6043 section 6.6</li>
 * <li>RFC6509 section 4.4</li>
 * <li>http://www.ietf.org/assignments/mikey-payloads/mikey-payloads.xml</li>
 * </ul>
 */
public final class IDRole {

	public static final byte IDR_I = 1;
	public static final byte IDR_R = 2;
	public static final byte IDR_KMS = 3;
	public static final byte IDR_PSK = 4;
	public static final byte IDR_APP = 5;
	public static final byte IDR_KMS_I = 6;
	public static final byte IDR_KMS_R = 7;

	private IDRole() {
	}
}
