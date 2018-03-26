package net.kapsch.kms.api.mikeysakke.crypto;

import java.math.BigInteger;

import net.kapsch.kms.api.bouncycastle.crypto.digests.SHA256Digest;
import net.kapsch.kms.api.bouncycastle.math.ec.ECConstants;
import net.kapsch.kms.api.bouncycastle.math.ec.ECCurve;
import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;

/**
 * Describes a parameter set for MIKEY-SAKKE message signing with ECCSI. The P-256
 * elliptic curve is used with SHA-256 as the hashing algorithm. See RFC 6509 section
 * 2.1.1 paragraph 2 and RFC 6507 section 4.1 for more details.
 */
public final class EccsiParameterSet {

	/**
	 * The prime number of size n bits. The finite field with p elements is denoted F_p
	 */
	public static final BigInteger p = new BigInteger(
			"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);

	/**
	 * The prime number q is defined to be the order of G in the elliptic curve E over
	 * finite field F_p.
	 */
	public static final BigInteger q = new BigInteger(
			"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

	/**
	 * The length of q in bytes.
	 */
	public static final int Q_LENGTH_IN_BYTES = 32;

	/**
	 * The elliptic curve E which represents y^2 = x^3 - 3x + B mod p defined over finite
	 * field F_p having subgroup of prime order q.
	 */
	public static final ECCurve ECurve = new ECCurve.Fp(p, ECConstants.THREE.negate(),
			ECConstants.ZERO);

	/**
	 * A generator point on the elliptic curve E which generates the subgroup of order q.
	 */
	public static final ECPoint G = ECurve.decodePoint(OctetString
			.fromHex("04"
					+ "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
					+ "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
			.getOctets());

	/**
	 * An octet string representation of the generator point G.
	 */
	public static final OctetString GString = new OctetString(EccsiParameterSet.G);

	/**
	 * The length of the hashing algorithm used (SHA256 gives 32 bytes).
	 */
	public static final int HASH_LENGTH = 32;

	/**
	 * The length of the hashing algorithm used (SHA256 gives 256 bits).
	 */
	public static final int HASH_LENGTH_BITS = 256;

	/**
	 * The length of a signature in bytes = (4 * hashLength) + 1. See RFC 6507 section
	 * 3.3.
	 */
	public static final int SIGNATURE_LENGTH = 129;

	/**
	 * The length of the Public Validation Token in bytes = (2 * hashLength) + 1. See RFC
	 * 6507 section 3.3.
	 */
	public static final int PVT_LENGTH = 65;

	/**
	 * The number of octets used to represent fields r and s in a signature. See RFC 6507
	 * section 4.1
	 */
	public static final int NBYTES = 32;

	/**
	 * Private constructor - should never be initialized.
	 */
	private EccsiParameterSet() {
		throw new IllegalStateException("should never be initialized");
	}

	/**
	 * The hashing algorithm to use in the procedure.
	 */
	public static void hash(byte[] data, int dataSize, byte[] result) {
		final SHA256Digest digest = new SHA256Digest();
		digest.update(data, 0, dataSize);
		digest.doFinal(result, 0);
	}
}
