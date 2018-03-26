package net.kapsch.kms.api.mikeysakke.crypto;

import java.math.BigInteger;

import net.kapsch.kms.api.bouncycastle.crypto.Digest;
import net.kapsch.kms.api.bouncycastle.math.ec.ECConstants;
import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.ProjFp;
import net.kapsch.kms.api.mikeysakke.utils.RandomGenerator;

/**
 * Static class used to perform all Sakke functions of the Mikey-Sakke protocol. See RFC
 * 6508 - Sakai-Kasahara Key Encryption (SAKKE) for more details.
 */
public final class Sakke {

	/**
	 * Private constructor - should never be initialized.
	 */
	private Sakke() {
		throw new IllegalStateException("should never be initialized");
	}

	/**
	 * Validate the receiver secret key delivered to the user given by their identifier.
	 * Returns true on successful validate, false otherwise. See RFC 6508 Section 6.1.2
	 * for more details.
	 *
	 * @param identifier the identity of the owner of the receiver secret key
	 * @param kmsPublicZString the KMS Public Key
	 * @param rskString the Receiver Secret Key (unique to the owner)
	 * @param parameterSet the Sakke parameter set to use
	 * @return true if the validation was successful
	 */
	public static boolean validateReceiverSecretKey(final OctetString identifier,
			final OctetString kmsPublicZString, final OctetString rskString,
			final int parameterSet) {

		SakkeParameterSet params = getParamSet(parameterSet);

		// Upon receipt of key material, each user MUST verify its RSK
		// otherwise known as (K_(a,T)). For Identifier 'a', RSKs from
		// KMS_T are verified by checking that the following equation
		// holds: < [a]P + Z, RSK > = g, where 'a' is interpreted as an integer.

		BigInteger a = new BigInteger(1, identifier.getOctets());

		// Calculate aP + Z
		ECPoint aP = params.pointP().multiply(a);
		ECPoint Z = params.curve().decodePoint(kmsPublicZString.getOctets());
		ECPoint aP_plus_Z = aP.add(Z);

		// Calculate pairing
		ECPoint RSK = params.curve().decodePoint(rskString.getOctets());
		BigInteger pairing = computePairing(aP_plus_Z, RSK, params);

		// if the pairing matches g, RSK is validated
		return pairing.equals(params.g());
	}

	/**
	 * Using the random number generator randomize, generate a Shared Secret Value (SSV)
	 * and corresponding SAKKE Encapsulated Data (SED) for the SAKKE Encapsulated Data
	 * used to transmit the SSV securely to the user identified by the identifier and
	 * return the Shared Secret Value SSV, a cryptographically strong random number.
	 * Returns empty string on failure See RFC 6508 Section 6.2.1 for more details.
	 *
	 * @param sakkeEncData The generated SAKKE Encapsulated Data
	 * @param targetIdentifier The identifier of the intended recipient of the generated
	 * SED
	 * @param parameterSet The SAKKE parameter set to use for the encryption
	 * @param kmsPublicZString The KMS Public Key
	 * @param randomize The random number generator to use to generate the SSV
	 * @return The SSV generated
	 */
	public static OctetString generateSharedSecretAndSED(final OctetString sakkeEncData,
			final OctetString targetIdentifier, final int parameterSet,
			final OctetString kmsPublicZString, final RandomGenerator randomize) {

		SakkeParameterSet params = getParamSet(parameterSet);
		//
		// 1) Select random ephemeral integer for SSV in [0,2^n)
		//
		OctetString ssvString = randomize.generate(params.nBytes());
		//
		// 2) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )
		//
		OctetString ssvAndb = new OctetString();
		ssvAndb.append(ssvString);
		ssvAndb.append(targetIdentifier);
		BigInteger r = hashToIntegerRangeSHA256(ssvAndb, params.q(), params.hash());
		//
		// 3) Compute R_(b,S) = [r]([b]P + Z) in E(F_p)
		//
		// This is equivalent to [r][b]P + [r]Z which we can use Shamirs trick
		// to calculate
		ECPoint Z = params.curve().decodePoint(kmsPublicZString.getOctets());
		BigInteger b = new BigInteger(1, targetIdentifier.getOctets());

		// Use standard method for calculation, instead of CAlgorithms.shamirsTrick.
		// Standard method has better performance.

		// long t1 = System.currentTimeMillis();
		// BigInteger rb = b.multiply(r);

		// ECPoint R = ECAlgorithms.shamirsTrick(params.pointP(), rb, Z, r);

		// long t3 = System.currentTimeMillis();
		ECPoint R = params.pointP().multiply(b).add(Z).multiply(r);

		// long t4 = System.currentTimeMillis();
		// System.out.println((t3-t1) + " " + new OctetString(R));
		// System.out.println((t4-t3) + " " + new OctetString(R));

		// 4) Compute the HINT, H; //NOSONAR
		//
		// 4.a) Compute g^r.
		//
		OctetString g_pow_r_String = null;
		if (!r.equals(BigInteger.ZERO)) {
			ProjFp g = new ProjFp(BigInteger.ONE, params.g(), params.p());
			g = g.modPow(r);

			// Form representation of PF_p (x_1, x_2) in F_p (x_2/x_1 mod p)
			BigInteger g_pow_r = g.getX1().modInverse(params.p());
			g_pow_r = g_pow_r.multiply(g.getX2());
			g_pow_r = g_pow_r.mod(params.p());
			g_pow_r_String = new OctetString(g_pow_r, params.pLengthBytes());
		}
		//
		// 4.b) Compute H := SSV XOR HashToIntegerRange( g^r, 2^n, Hash ); //NOSONAR
		//
		BigInteger two_pow_n = BigInteger.ONE.shiftLeft(params.n());
		BigInteger hashedRange = hashToIntegerRangeSHA256(g_pow_r_String, two_pow_n,
				params.hash());

		BigInteger ssv = new BigInteger(1, ssvString.getOctets());
		BigInteger h = ssv.xor(hashedRange);
		OctetString hString = new OctetString(h, params.nBytes());
		//
		// 5) Form the SED ( R_(b,S), H )
		//
		OctetString SED = new OctetString();
		SED.append(new OctetString(R));
		SED.append(hString);
		sakkeEncData.setOctets(SED);

		// 6) Output SSV
		return ssvString;
	}

	/**
	 * Extracts the SSV (shared secret value) from a received SED (SAKKE encapsulated
	 * data) using the receivers identity, their RSK and the KMS public key. See RFC 6508
	 * Section 6.2.2 for more details.
	 *
	 * @param sakkeEncData The SAKKE encapsulated data
	 * @param identifier The receivers identifier
	 * @param parameterSet The SAKKE parameter set to use for the encryption
	 * @param rskString The Receivers Secret Key
	 * @param kmsPublicZString The KMS Public Key
	 * @return The SSV (Shared Secret Value) contained in the data
	 */
	public static OctetString extractSharedSecret(final OctetString sakkeEncData,
			final OctetString identifier, final int parameterSet,
			final OctetString rskString, final OctetString kmsPublicZString) {

		SakkeParameterSet params = getParamSet(parameterSet);

		// Check that the SAKKE encapsulated data is the correct size
		if (sakkeEncData.size() != params.encDataLengthBytes()) {
			throw new IllegalArgumentException("Incorrect length of data inputted, "
					+ "expected : " + params.encDataLengthBytes() + ", " + "actual :"
					+ sakkeEncData.size());
		}
		//
		// 1) Parse the Encapsulated Data ( R_(b,S), H ), //NOSONAR
		// and extract R_(b,S) and H; //NOSONAR

		OctetString RString = sakkeEncData.subString(0, params.rLengthBytes());
		ECPoint R = params.curve().decodePoint(RString.getOctets());
		OctetString hString = sakkeEncData.subString(params.rLengthBytes());
		//
		// 2) Compute w := < R, RSK >
		//
		OctetString wString;
		ECPoint RSK = params.curve().decodePoint(rskString.getOctets());
		BigInteger w = computePairing(R, RSK, params);
		wString = new OctetString(w, params.pLengthBytes());
		//
		// 3) Compute SSV := H XOR HashToIntegerRange( w, 2^n, Hash ); //NOSONAR
		//
		BigInteger two_pow_n = BigInteger.ONE.shiftLeft(params.n());
		BigInteger hashed = hashToIntegerRangeSHA256(wString, two_pow_n, params.hash());

		BigInteger h = new BigInteger(1, hString.getOctets());
		BigInteger ssv = h.xor(hashed);
		OctetString ssvString = new OctetString(ssv, params.nBytes());
		//
		// 4) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )
		//
		OctetString ssvAndb = new OctetString();
		ssvAndb.append(ssvString);
		ssvAndb.append(identifier);
		BigInteger r = hashToIntegerRangeSHA256(ssvAndb, params.q(), params.hash());
		//
		// 5) Compute TEST = [r][b]P + [r]Z_S = [r]([b]P + Z_S)
		//
		ECPoint Z = params.curve().decodePoint(kmsPublicZString.getOctets());

		final BigInteger b = new BigInteger(1, identifier.getOctets());

		// Use standard method for calculation, instead of CAlgorithms.shamirsTrick.
		// Standard method has better performance.

		// long t1 = System.currentTimeMillis();
		// BigInteger rb = b.multiply(r);
		// ECPoint TEST = ECAlgorithms.shamirsTrick(params.pointP(), rb, Z, r);
		// long t3 = System.currentTimeMillis();
		ECPoint TEST = params.pointP().multiply(b).add(Z).multiply(r);

		// long t4 = System.currentTimeMillis();
		// System.out.println((t3-t1) + " " + new OctetString(R));
		// System.out.println((t4-t3) + " " + new OctetString(R1));

		// Check if the TEST value is correct
		if (TEST.equals(R)) {
			return ssvString;
		}
		else {
			throw new SakkeException("Extraction of SSV failed.");
		}
	}

	/**
	 * Returns the parameter set to use for the SAKKE protocol. Will throw an exception if
	 * the parameter set is not supported.
	 *
	 * @param parameterSet The parameter set to use
	 * @return The corresponding parameter set object
	 */
	public static SakkeParameterSet1 getParamSet(final int parameterSet) {
		if (parameterSet != 1) {
			throw new IllegalArgumentException(
					"Only SAKKE parameter set 1 is supported.");
		}
		return new SakkeParameterSet1();
	}

	/**
	 * Utility function to hash strings to an integer range. See RFC 6508 section 5.1 for
	 * more details.
	 *
	 * @param s An octet string to hash
	 * @param n The range of the integer to hash to (0, n-1)
	 * @param hashfn The SHA256 hash function to use
	 * @return The number representing the hashed string
	 */
	private static BigInteger hashToIntegerRangeSHA256(final OctetString s,
			final BigInteger n, final Digest hashfn) {
		// Ensure we are working with SHA256 only
		if (!"SHA-256".equals(hashfn.getAlgorithmName())) {
			throw new IllegalArgumentException(
					"Incorrect hashing function, only SHA256 supported.");
		}
		// Store the hash length used, which in this case is always 256
		final int HASH_LENGTH_BYTES = 32;
		//
		// 1) A = hashfn(s)
		//
		OctetString aString = new OctetString(HASH_LENGTH_BYTES);
		hashfn.update(s.getOctets(), 0, s.size());
		hashfn.doFinal(aString.getOctets(), 0);
		//
		// 2) let h_0 = 00....00, a string of null bits of length hashlen bits
		//
		// The octet string constructor will create empty bytes
		OctetString hString = new OctetString(HASH_LENGTH_BYTES);
		//
		// 3) l = ceiling(lg(n)/hashlength)
		//
		// This is equivalent to adding the 255 to the bit length of n
		// and bit shifting it lg(HASH_LENGTH) = 8 places to the right
		final int HASH_LENGTH_BITS_MINUS_ONE = 255;
		final int LG_HASH_LENGTH_BITS = 8;
		int l = (n.bitLength() + HASH_LENGTH_BITS_MINUS_ONE) >> LG_HASH_LENGTH_BITS;
		//
		// 4) For i in [1, l] do
		//
		OctetString vprime = null;
		OctetString vi = new OctetString(HASH_LENGTH_BYTES);
		for (int i = 1; i <= l; i++) {

			//
			// a) Let h_i = hashfn(h_(i - 1))
			//
			hashfn.update(hString.getOctets(), 0, hString.size());
			hashfn.doFinal(hString.getOctets(), 0);
			//
			// b) Let v_i = hashfn(h_i || A), where || denotes concatenation //NOSONAR
			//
			OctetString temp = new OctetString(hString);
			temp.append(aString);
			hashfn.update(temp.getOctets(), 0, temp.size());
			hashfn.doFinal(vi.getOctets(), 0);
			//
			// 5) Let v' = v_1 || ... || v_l //NOSONAR
			//
			// As we create v_i, concatenate onto the previous calculations.
			if (i == 1) {
				vprime = new OctetString(vi);
			}
			else if (vprime != null) {
				vprime.append(vi);
			}
			else {
				throw new NullPointerException("vprime can't be null");
			}
		}
		//
		// 5) Let v = v' mod n
		//
		if (vprime != null) {
			BigInteger vp = new BigInteger(1, vprime.getOctets());
			BigInteger v = vp.mod(n);
			return v;
		}
		else {
			throw new NullPointerException("vprime can't be null");
		}
	}

	/**
	 * Implements the Tate-Lichtenbaum Pairing for elliptical points, w = \<R,Q\>. See
	 * RFC6508 section 3.2 for more details.
	 *
	 * @param pointR The first elliptical point in the pairing
	 * @param pointQ The second elliptical point in the pairing
	 * @param params The SAKKE parameter set to use
	 * @return The result w
	 */
	private static BigInteger computePairing(final ECPoint pointR, final ECPoint pointQ,
			final SakkeParameterSet params) {
		if (!(params instanceof SakkeParameterSet1)) {
			throw new IllegalArgumentException(
					"Compute pairing is only valid for SAKKE parameter set 1");
		}

		// Initialize variables v, C.
		// Later, we use the fact that for SAKKE parameter set 1,
		// c = (p+1)/q = 4.
		ProjFp v = new ProjFp(BigInteger.ONE, BigInteger.ZERO, params.p());
		ECPoint C = pointR;

		BigInteger Qx = pointQ.getX().toBigInteger();
		BigInteger Qy = pointQ.getY().toBigInteger();
		BigInteger Rx = pointR.getX().toBigInteger();
		BigInteger Ry = pointR.getY().toBigInteger();
		BigInteger Cx = C.getX().toBigInteger();
		BigInteger Cy = C.getY().toBigInteger();

		// For bits of q-1, start with the second most significant bit, ending
		// with
		// the least significant bit, do...
		BigInteger q_minus_one = params.q().subtract(BigInteger.ONE);
		for (int N = (q_minus_one.bitLength()) - 1; N != 0; --N) {

			// gradient of line through C, C, [-2]C. Note that we be extracting
			// the factor
			// of (1 / 2*C_y) to avoid division as overall factors are ignored
			// due to form
			// of the final result b/a

			// Calculate l = 3*(C_x^2 - 1); //NOSONAR
			BigInteger l = Cx.modPow(ECConstants.TWO, params.p());
			l = l.subtract(BigInteger.ONE);
			l = l.multiply(ECConstants.THREE);

			// Calculate t = Qx + Cx
			BigInteger t = Qx.add(Cx);

			// Calculate t = l * t = l * (Qx + Cx)
			t = l.multiply(t).mod(params.p());

			// Calculate Tx = Cy^2
			BigInteger Tx = Cy.modPow(ECConstants.TWO, params.p());

			// Calculate Tx = t - (2 * Tx) = l * (Qx + Cx) - 2Cy^2
			Tx = t.subtract(Tx.shiftLeft(1));
			Tx = Tx.mod(params.p());

			// Calculate Ty = 2 * Cy
			BigInteger Ty = Cy.shiftLeft(1);

			// Calculate Ty = Ty * Qy = 2 * Cy * Qy
			Ty = Ty.multiply(Qy);
			Ty = Ty.mod(params.p());

			ProjFp T = new ProjFp(Tx, Ty, params.p());

			// Calculate v = v^2 * T = v^2 * (Tx + iTy) = v^2 * (l(Qx + Cx) -
			// 2Cy^2 - i(2 Cy Qy))
			v = v.square();
			v = v.multiply(T);

			// Calculate C = 2C and refresh our Cx and Cy variables
			C = C.twice();
			Cx = C.getX().toBigInteger();
			Cy = C.getY().toBigInteger();

			if (q_minus_one.testBit(N - 1)) {
				// We are trying to calculate
				//
				// v = v * (l * (Qx + Cx) + i * Qy - Cy))
				//
				// where
				//
				// l = (Cy - Ry)/(Cx - Rx).
				//
				// This can be represented as
				//
				// v = ( v / (Cx - Rx) ) * (Tx + iTy)
				//
				// Where we define...
				//
				// Tx = Cy (Qx + Rx) - Ry (Qx + Cx)
				// Ty = Qy (Cx - Rx)
				//
				// The final result will only involve Ty/Tx so we do
				// not need to calculate the 1 /(Cx-Rx) factor as this will
				// cancel out

				// Calculate Tx = Cy ( Qx + Rx )
				Tx = Qx.add(Rx);
				Tx = Tx.multiply(Cy);
				Tx = Tx.mod(params.p());

				// Calculate t = Ry ( Qx + Cx )
				t = Qx.add(Cx);
				t = t.multiply(Ry);
				t = t.mod(params.p());

				// Calculate Tx = Tx - t = Cy (Qx + Rx) - Ry (Qx + Cx)
				Tx = Tx.subtract(t);
				Tx = Tx.mod(params.p());

				// Calculate Ty = Qy (Cx - Rx)
				Ty = Cx.subtract(Rx);
				Ty = Ty.multiply(Qy);
				Ty = Ty.mod(params.p());

				T = new ProjFp(Tx, Ty, params.p());

				// Calculate v = v * (Tx + iTy)
				v = v.multiply(T);

				// Add R to C and refresh our Cx and Cy variables
				C = C.add(pointR);
				Cx = C.getX().toBigInteger();
				Cy = C.getY().toBigInteger();
			}

		}
		// Calculate v^c = v^(p+1/q), which in this case is v^4 ( or (v^2) ^2 )
		v = v.square();
		v = v.square();

		// Calculate w = 1 / v_x
		BigInteger w = v.getX1().abs().modInverse(params.p());

		// Calculate w = w * v_y = v_y / v_x
		w = w.multiply(v.getX2());
		w = w.mod(params.p());
		return w;
	}
}
