package net.kapsch.kms.api.bouncycastle.math.field;

public interface Polynomial {
	int getDegree();

	// BigInteger[] getCoefficients();

	int[] getExponentsPresent();

	// Term[] getNonZeroTerms();
}
