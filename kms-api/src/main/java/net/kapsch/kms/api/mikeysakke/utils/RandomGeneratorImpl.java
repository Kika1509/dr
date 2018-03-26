package net.kapsch.kms.api.mikeysakke.utils;

import java.security.SecureRandom;

public class RandomGeneratorImpl implements RandomGenerator {
	@Override
	public OctetString generate(int n) {
		SecureRandom random = new SecureRandom();
		byte[] randBytes = new byte[n];
		random.nextBytes(randBytes);

		return new OctetString(randBytes);
	}
}
