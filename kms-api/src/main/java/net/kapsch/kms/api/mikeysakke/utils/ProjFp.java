package net.kapsch.kms.api.mikeysakke.utils;

import java.math.BigInteger;

/**
 * Represents element of finite filed PFp, which is a projectivization of Fp. See RFC 6508
 * section 2 for more details. These points are represented by a complex number.
 */
public class ProjFp {

	/**
	 * Real part of the element.
	 */
	private final BigInteger x1;

	/**
	 * Imaginary part of the element.
	 */
	private final BigInteger x2;

	/**
	 * The order of the finite field Fp.
	 */
	private final BigInteger p;

	/**
	 * Constructor for an element in PFp.
	 *
	 * @param realPart The real part of the element
	 * @param imagPart The imaginary part of the element
	 * @param prime The prime the finite field Fp is over
	 */
	public ProjFp(final BigInteger realPart, final BigInteger imagPart,
			final BigInteger prime) {
		this.x1 = realPart;
		this.x2 = imagPart;
		this.p = prime;
	}

	/**
	 * Getter for the real part of the element.
	 *
	 * @return The real part of the element
	 */
	public BigInteger getX1() {
		return this.x1;
	}

	/**
	 * Getter for the imaginary part of the element.
	 *
	 * @return The imaginary part of the element
	 */
	public BigInteger getX2() {
		return this.x2;
	}

	/**
	 * Squares an element of PFp.
	 *
	 * @return The element squared
	 */
	public ProjFp square() {
		// Consider this element X = x1 + i x2

		// Store t1 = x1 + x2
		BigInteger t1 = this.x1.add(this.x2);

		// Store t2 = x1 - x2
		BigInteger t2 = this.x1.subtract(this.x2);

		// Create new result
		// R = r1 + i r2
		// R = (t1 * t2) + i (2 * x1 * x2)
		// R = (x1^2 - x2^2) + i (2 * x1 * x2)
		// R = X^2

		// Store r1 = t1 * t2
		BigInteger r1 = (t1.multiply(t2)).mod(this.p);

		// Store r2 = 2 * x1 * x2
		BigInteger r2 = ((this.x1.multiply(this.x2)).shiftLeft(1)).mod(this.p);

		ProjFp R = new ProjFp(r1, r2, this.p);
		return R;
	}

	/**
	 * Multiplies two elements of PFp.
	 *
	 * @param elementA The element to multiply with this element
	 * @return The result of the multiplication
	 */
	public ProjFp multiply(final ProjFp elementA) {
		// Consider the following
		//
		// X*A
		// = (x1 + i x2)(a1 + i a2)
		// = x1 a1 + i x1 a2 + i x2 a1 - x2 a2
		// = (x1 a1 - x2 a2) + i (x1 a2 + x2 a1)
		// = ( t1 - t2 ) + i ( t3 + t4 )
		BigInteger t1 = this.x1.multiply(elementA.x1);
		BigInteger t2 = this.x2.multiply(elementA.x2);
		BigInteger t3 = this.x1.multiply(elementA.x2);
		BigInteger t4 = this.x2.multiply(elementA.x1);

		ProjFp R = new ProjFp(t1.subtract(t2).mod(this.p), t3.add(t4).mod(this.p),
				this.p);
		return R;

	}

	/**
	 * Raises the element to power n modulo p.
	 *
	 * @param n The power to raise the element to
	 * @return The result of the operation
	 */
	public ProjFp modPow(final BigInteger n) {
		// Throw exception if being asked to raise the element to power 0
		if (n.equals(BigInteger.ZERO)) {
			throw new IllegalArgumentException("Raise to power 0 not implemented.");
		}

		// Create a element R to store the result (R = X)
		ProjFp result = new ProjFp(this.x1, this.x2, this.p);

		// Loop through all the bits of the power and depending on the bit
		// either set R = R^2 or R = ( R^2 ) * R
		for (int N = n.bitLength() - 1; N != 0; --N) {
			result = result.square();
			if (n.testBit(N - 1)) {
				result = result.multiply(this);
			}
		}
		return result;
	}

}
