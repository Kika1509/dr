package net.kapsch.kms.api.bouncycastle.math.ec.endo;

import net.kapsch.kms.api.bouncycastle.math.ec.ECPointMap;

public interface ECEndomorphism {
	ECPointMap getPointMap();

	boolean hasEfficientPointMap();
}
