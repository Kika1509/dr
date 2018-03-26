package net.kapsch.kms.api.mikeysakke.utils;

/**
 * Defines the interface used for generating random numbers for use in MIKEY-SAKKE
 * Encryption.
 */
public interface RandomGenerator {

	/**
	 * Signature for a function intended to fill an octet string with a cryptographically
	 * strong random integer in the range [0, 2^8n) where N is the number of octets in the
	 * string.
	 *
	 * @param n The number of octets to fill.
	 * @return The randomly generated octet string.
	 */
	OctetString generate(int n);

}
