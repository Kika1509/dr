package net.kapsch.kms.api.mikeysakke;

public final class PurposeTag {

	/**
	 * the GMK shall be used for group communications.
	 */
	public static final byte GMK = 0;

	/**
	 * the PCK shall be used to protect Private Call communications.
	 */
	public static final byte PCK = 1;

	/**
	 * the CSK shall be used to protect application signalling (XML and SRTCP) between the
	 * MCPTT client and MCPTT domain.
	 */
	public static final byte CSK = 2;

	/**
	 * the SPK shall be used to protect application signalling (XML and SRTCP) between
	 * servers in MCPTT domain(s).
	 */
	public static final byte SPK = 3;

	/**
	 * The MKFC shall be used to protect multicast floor control signalling from the MCPTT
	 * Server to MCPTT clients.
	 */
	public static final byte MKFC = 4;

	/**
	 * The MSCCK shall be used to protect MBMS subchannel control messages from the MCPTT
	 * Server to MCPTT clients.
	 */
	public static final byte MSCCK = 5;

	private PurposeTag() {
	}
}
