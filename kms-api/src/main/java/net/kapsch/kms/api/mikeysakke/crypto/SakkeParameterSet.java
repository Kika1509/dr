package net.kapsch.kms.api.mikeysakke.crypto;

import java.math.BigInteger;

import net.kapsch.kms.api.bouncycastle.crypto.Digest;
import net.kapsch.kms.api.bouncycastle.math.ec.ECCurve;
import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;

/**
 * Abstract class used to define the required parameters and useful pre calculated values
 * to perform SAKKE encryption.
 */
public abstract class SakkeParameterSet {
	/**
	 * The identifier used for this parameter set.
	 */
	public abstract int parameterSetIdentifer();

	/**
	 * A prime number which is the order of the finite field F_p.
	 */
	public abstract BigInteger p();

	/**
	 * Length of p in bytes.
	 */
	public abstract int pLengthBytes();

	/**
	 * An odd prime that divides p + 1.
	 */
	public abstract BigInteger q();

	/**
	 * The point P in the elliptic curve E(F_p) that generates the cyclic subgroup of
	 * order q.
	 */
	public abstract ECPoint pointP();

	/**
	 * The elliptic curve defined over finite field F_p. The curve follows the equation
	 * y^2 = x^3 - 3 * x modulo p.
	 */
	public abstract ECCurve curve();

	/**
	 * The pre-calculated value of {@literal <P,P>} (Tate-Lichtenbaum Pairing).
	 */
	public abstract BigInteger g();

	/**
	 * The hashing algorithm to use.
	 */
	public abstract Digest hash();

	/**
	 * The size of the symmetric keys in bits to be exchanged by SAKKE.
	 */
	public abstract int n();

	/**
	 * The size of the symmetric keys in bytes to be exchanged by SAKKE.
	 */
	public abstract int nBytes();

	/**
	 * The length of variable R (which is a point on elliptic curve E) when extracted from
	 * the SAKKE encapsulated data. See RFC 6508 section 4 (Points on E) and section 6.2.2
	 * for more details. An elliptic point should be stored in the form 0x04 || x' || y'
	 * where the length of the coordinated L = Ceiling(lg(p)/8) = size in p in bytes.
	 * Therefore the expected length should be (2 * LengthInBytes(p) ) + 1
	 */
	public abstract int rLengthBytes();

	/**
	 * The expected length of the SAKKE encapsulated data. See RFC 6508 section 4
	 * (Encapsulated Data) and for more details. The length should be ( 2 *
	 * LengthInBytes(R) ) + LengthInBytes(n) + 1.
	 */
	public abstract int encDataLengthBytes();
}
