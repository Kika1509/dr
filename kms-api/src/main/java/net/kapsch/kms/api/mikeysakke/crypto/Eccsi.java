package net.kapsch.kms.api.mikeysakke.crypto;

import java.math.BigInteger;

import net.kapsch.kms.api.bouncycastle.math.ec.ECAlgorithms;
import net.kapsch.kms.api.bouncycastle.math.ec.ECConstants;
import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.RandomGenerator;

/**
 * Static class used to perform all major functions of the ECCSI protocol. See RFC 6507 -
 * Elliptic Curve-Based Certificateless Signatures for Identity-Based Encryption (ECCSI)
 * for more details.
 */
public final class Eccsi {

	/**
	 * Private constructor - should never be initialized.
	 */
	private Eccsi() {
		throw new IllegalStateException("should never be initialized");
	}

	/**
	 * Validate the message signing keys delivered to the user given by identifier. If
	 * successful, the value of "HS" calculated during the validation algorithm is stored
	 * as output for later use within Sign() below and true is returned. See RFC 6507
	 * Section 5.1.2 for more details.
	 *
	 * @param identifier the identity of the owner of the keys
	 * @param pvtString the Public Validation Token to verify
	 * @param kpakString the KMS Public Authentication Key
	 * @param sskString the Secret Signing Key to verify
	 * @param hsStringOut a hashed value that can be used when signing using these keys
	 * @return if the validation was successful
	 */
	public static boolean validateSigningKeys(final OctetString identifier,
			final OctetString pvtString, final OctetString kpakString,
			final OctetString sskString, final OctetString hsStringOut) {

		// 1) Validate that the PVT lies on the curve E
		ECPoint PVT = null;

		// if point is not on curve, ECPoint constructor will fail.
		try {
			PVT = EccsiParameterSet.ECurve.decodePoint(pvtString.getOctets());
		}
		catch (Exception e) {
			throw new EccsiException("Point is not on curve.", e);
		}

		// 2) Compute HS = hash( G || KPAK || ID || PVT ) //NOSONAR
		OctetString unhashedHS = new OctetString();
		unhashedHS.append(EccsiParameterSet.GString);
		unhashedHS.append(kpakString);
		unhashedHS.append(identifier);
		unhashedHS.append(pvtString);

		OctetString hashedSign = new OctetString(EccsiParameterSet.HASH_LENGTH);
		EccsiParameterSet.hash(unhashedHS.getOctets(), unhashedHS.size(),
				hashedSign.getOctets());

		// Return HS for later use by Sign().
		hsStringOut.setOctets(hashedSign);
		BigInteger hs = new BigInteger(1, hashedSign.getOctets());
		//
		// 3) Validate that KPAK = [SSK]G - [HS]PVT
		//
		// For efficiency, validate that KPAK + [HS]PVT = [SSK]G
		ECPoint KPAK = EccsiParameterSet.ECurve.decodePoint(kpakString.getOctets());
		ECPoint lhs = KPAK.add(PVT.multiply(hs));

		BigInteger ssk = new BigInteger(1, sskString.getOctets());
		ECPoint rhs = EccsiParameterSet.G.multiply(ssk);

		// Return the result
		return lhs.equals(rhs);
	}

	/**
	 * Sign the message given using the key material for the given and the random number
	 * generator. The signature is returned if successful, otherwise null is returned. See
	 * RFC 6507 Section 5.2.1 for more details.
	 *
	 * @param messageToSign the message to create a signature for
	 * @param pvtString the Public Validation Token to verify
	 * @param sskString the Secret Signing Key to verify
	 * @param hsString a hashed value calculated from verifying the signing keys
	 * @param random a random number generator
	 * @return the signature for the message
	 */

	// TODO: find out why specification asks for kpakString parameter and it is never used

	public static OctetString sign(final OctetString messageToSign,
			final OctetString pvtString, final OctetString sskString,
			final OctetString hsString, final RandomGenerator random) {

		OctetString rand = null;

		// Initialize variables for loop
		BigInteger j;
		BigInteger he_plus_rSSK = BigInteger.ZERO;
		BigInteger r;
		OctetString rString = null;
		OctetString heString = null;

		do {
			//
			// 1) Choose a random (ephemeral) non-zero value j in F_q
			//
			rand = random.generate(EccsiParameterSet.Q_LENGTH_IN_BYTES);

			// ensure j is in F_q
			j = new BigInteger(1, rand.getOctets());
			j = j.mod(EccsiParameterSet.q);

			// if j is zero, restart the process
			if (rand.empty() || rand.allZeroes() || j.equals(BigInteger.ZERO)) {
				continue;
			}
			//
			// 2) Compute J = (Jx,Jy) = [j]G and assign Jx to r
			//
			ECPoint J = EccsiParameterSet.G.multiply(j);
			r = J.getX().toBigInteger();
			//
			// 3) Compute HE = hash( HS || r || M ) Note that HS should already //NOSONAR
			// have been calculated when verifying
			// the signing keys
			// received by the KMS, so we assume this has been cached and passed
			// in already.
			if (hsString == null || hsString.empty()) {
				throw new IllegalArgumentException(
						"Implementation currently requires cached HS");
			}

			rString = new OctetString(r, EccsiParameterSet.NBYTES);
			OctetString undigestedHE = new OctetString();
			undigestedHE.append(hsString);
			undigestedHE.append(rString);
			undigestedHE.append(messageToSign);

			// Hash the concatenated octet string
			heString = new OctetString(EccsiParameterSet.HASH_LENGTH);
			EccsiParameterSet.hash(undigestedHE.getOctets(), undigestedHE.size(),
					heString.getOctets());

			// 4) Verify that HE + r * SSK is non-zero (mod q)
			BigInteger ssk = new BigInteger(1, sskString.getOctets());
			BigInteger he = new BigInteger(1, heString.getOctets());
			he_plus_rSSK = r.multiply(ssk).mod(EccsiParameterSet.q);
			he_plus_rSSK = he_plus_rSSK.add(he).mod(EccsiParameterSet.q);

			// If it is zero restart the process
		}
		while (he_plus_rSSK.equals(BigInteger.ZERO));
		//
		// 5) Compute s' = ( (( HE + r * SSK )^-1) * j ) (mod q) and erase
		// ephemeral j
		//
		// Note that we can use the verify value (HE + r* SSK) from the previous
		// step
		BigInteger sprime = he_plus_rSSK.modInverse(EccsiParameterSet.q);
		sprime = sprime.multiply(j).mod(EccsiParameterSet.q);

		// Remove all references to j (and the random number behind j)
		//
		// 6) Set s = q - s' if octet_count(s) > N
		//
		// Check if the octet count is higher for s ( we check if the number of
		// bits of s are greater than the number of bits that N can hold).
		OctetString s = null;
		if (sprime.bitLength() > EccsiParameterSet.HASH_LENGTH_BITS) {
			s = new OctetString(EccsiParameterSet.q.subtract(sprime),
					EccsiParameterSet.NBYTES);
		}
		else {
			s = new OctetString(sprime, EccsiParameterSet.NBYTES);
		}
		//
		// 7) Output the signature = ( r || s || PVT ) //NOSONAR
		//
		OctetString signature = new OctetString();
		signature.append(rString);
		signature.append(s);
		signature.append(pvtString);

		// Verify the message is the correct length (see RFC 6507 Section 3.3)
		if (signature.size() != EccsiParameterSet.SIGNATURE_LENGTH) {
			throw new EccsiException("The signature should be "
					+ String.valueOf(EccsiParameterSet.SIGNATURE_LENGTH)
					+ " bytes in legth.");
		}
		return signature;
	}

	/**
	 * Verifies a given message against a given signature, returning true if the message
	 * is verified, otherwise false. See RFC 6507 Section 5.2.2 for more details.
	 *
	 * @param messageToVerify the message to be verified
	 * @param signature the signature to verify the message against
	 * @param identifier the identity of the owner of the message
	 * @param kpakString the KMS Public Authentication Key
	 * @return true if the message has been verified
	 */
	public static boolean verify(final OctetString messageToVerify,
			final OctetString signature, final OctetString identifier,
			final OctetString kpakString) {
		// Check that the signature is the correct size; two
		// N-octet integers r and s, plus an elliptical curve point PVT
		// over E expressed in uncompressed form with length 2N -- See
		// RFC6507 3.3)
		if (signature.size() != EccsiParameterSet.SIGNATURE_LENGTH) {
			return false;
		}

		// Extract the r,s and PVT from the signature
		int r_len = EccsiParameterSet.HASH_LENGTH;
		int s_len = EccsiParameterSet.HASH_LENGTH;

		OctetString rString = signature.subString(0, r_len);
		OctetString sString = signature.subString(r_len, s_len);
		OctetString pvt = signature.subString(r_len + s_len,
				EccsiParameterSet.PVT_LENGTH);
		//
		// 1) Check that PVT lies on the elliptical curve E
		//
		ECPoint PVT;
		// if point is not on curve, ECPoint constructor will fail.
		try {
			PVT = EccsiParameterSet.ECurve.decodePoint(pvt.getOctets());
		}
		catch (Exception e) {
			return false;
		}
		//
		// 2) Compute HS = hash( G || KPAK || ID || PVT ) //NOSONAR
		//
		OctetString unhashedHS = new OctetString();
		unhashedHS.append(EccsiParameterSet.GString);
		unhashedHS.append(kpakString);
		unhashedHS.append(identifier);
		unhashedHS.append(pvt);

		OctetString hsString = new OctetString(EccsiParameterSet.HASH_LENGTH);
		EccsiParameterSet.hash(unhashedHS.getOctets(), unhashedHS.size(),
				hsString.getOctets());

		//
		// 3) Compute HE = hash( HS || r || M ) //NOSONAR
		//
		OctetString unhashedHE = new OctetString();
		unhashedHE.append(hsString);
		unhashedHE.append(rString);
		unhashedHE.append(messageToVerify);

		OctetString heString = new OctetString(EccsiParameterSet.HASH_LENGTH);
		EccsiParameterSet.hash(unhashedHE.getOctets(), unhashedHE.size(),
				heString.getOctets());
		//
		// 4) Y = [HS]PVT + KPAK
		//
		ECPoint KPAK = EccsiParameterSet.ECurve.decodePoint(kpakString.getOctets());
		BigInteger hs = new BigInteger(1, hsString.getOctets());
		//
		// 5) Compute J = [s]( [HE]G + [r]Y )
		//
		// This is equivalent to ...
		// J = [s][HE]G mod (q) + [s][r][HS]PVT mod (q) + [s][r]KPAK mod (q)
		BigInteger r = new BigInteger(1, rString.getOctets());
		BigInteger he = new BigInteger(1, heString.getOctets());
		BigInteger s = new BigInteger(1, sString.getOctets());

		BigInteger she = s.multiply(he).mod(EccsiParameterSet.q);
		BigInteger sr = s.multiply(r).mod(EccsiParameterSet.q);
		BigInteger srhs = sr.multiply(hs).mod(EccsiParameterSet.q);

		// Use ECAlgorithms.shamirsTrick method for calculation. It has better
		// performance.
		// long t1 = System.currentTimeMillis();

		// Use Shamirs trick to do the first two multiplications
		// [s][HE]G + [s][r][HS]PVT and then add on [s][r]KPAK
		ECPoint J = ECAlgorithms.shamirsTrick(EccsiParameterSet.G, she, PVT, srhs)
				.add(KPAK.multiply(sr));

		// long t3 = System.currentTimeMillis();
		// ECPoint J1 =
		// EccsiParameterSet.G.multiply(she).add(PVT.multiply(srhs)).add(KPAK.multiply(sr));
		//
		// long t4 = System.currentTimeMillis();
		//
		// System.out.println((t3-t1) + " " + new OctetString(J));
		// System.out.println((t4-t3) + " " + new OctetString(J1));

		//
		// 6) Viewing J in affine coordinates (Jx,Jy), check that
		//
		// Jx = r mod p, and that Jx mod p != 0.
		//
		// Note: If Jx = r mod p and Jx != 0, then Jx mod p != 0.
		//
		BigInteger j_x = J.getX().toBigInteger();
		return (j_x.equals(r.mod(EccsiParameterSet.p)) && !j_x.equals(ECConstants.ZERO));
	}
}
