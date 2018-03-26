package net.kapsch.kms.api.bouncycastle.math.field;

import java.math.BigInteger;

public interface FiniteField {
	BigInteger getCharacteristic();

	int getDimension();
}
