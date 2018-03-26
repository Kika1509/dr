package net.kapsch.kms.api.bouncycastle.math.ec;

public interface ECLookupTable {
	int getSize();

	ECPoint lookup(int index);
}
