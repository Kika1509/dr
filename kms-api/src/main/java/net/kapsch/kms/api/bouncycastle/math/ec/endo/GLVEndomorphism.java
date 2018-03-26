package net.kapsch.kms.api.bouncycastle.math.ec.endo;

import java.math.BigInteger;

public interface GLVEndomorphism extends ECEndomorphism {
	BigInteger[] decomposeScalar(BigInteger k);
}
