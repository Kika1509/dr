package net.kapsch.kmc.api.service.mikey.tables;

import net.kapsch.kmc.api.service.mikey.PolicyParam;

public final class SRTPDefaultProfile {

	/**
	 * Table E.2-1: MIKEY Group call SRTP Default Profile. See specification 3GPP 33.179
	 * version 13.4.0 (section E.2 MIKEY message structure for GMK distribution).
	 *
	 * @return security properties of group communications
	 */
	public static PolicyParam[] getGroupCallPolicyParams() {
		return new PolicyParam[] { new PolicyParam((byte) 0, (byte) 1, new byte[] { 6 }),
				new PolicyParam((byte) 1, (byte) 1, new byte[] { 16 }),
				new PolicyParam((byte) 2, (byte) 1, new byte[] { 4 }),
				new PolicyParam((byte) 4, (byte) 1, new byte[] { 12 }),
				new PolicyParam((byte) 5, (byte) 1, new byte[] { 0 }),
				new PolicyParam((byte) 6, (byte) 1, new byte[] { 0 }),
				new PolicyParam((byte) 13, (byte) 1, new byte[] { 1 }),
				new PolicyParam((byte) 18, (byte) 1, new byte[] { 4 }),
				new PolicyParam((byte) 19, (byte) 1, new byte[] { 0 }),
				new PolicyParam((byte) 20, (byte) 1, new byte[] { 16 }) };
	}

	/**
	 * Table E.3-1: MIKEY Group call SRTP Default Profile. See specification 3GPP 33.179
	 * version 13.4.0 (section E.3 MIKEY message structure for PCK distribution).
	 *
	 * @return security properties of private calls
	 */
	public static PolicyParam[] getPrivateCallPolicyParams() {
		return new PolicyParam[] { new PolicyParam((byte) 0, (byte) 1, new byte[] { 6 }),
				new PolicyParam((byte) 1, (byte) 1, new byte[] { 16 }),
				new PolicyParam((byte) 4, (byte) 1, new byte[] { 12 }),
				new PolicyParam((byte) 5, (byte) 1, new byte[] { 0 }),
				new PolicyParam((byte) 6, (byte) 1, new byte[] { 0 }),
				new PolicyParam((byte) 20, (byte) 1, new byte[] { 16 }) };
	}

	private SRTPDefaultProfile() {
	}
}
