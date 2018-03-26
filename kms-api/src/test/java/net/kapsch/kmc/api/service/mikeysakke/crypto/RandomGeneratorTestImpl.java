package net.kapsch.kmc.api.service.mikeysakke.crypto;

import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.RandomGenerator;

public class RandomGeneratorTestImpl implements RandomGenerator {
	@Override
	public OctetString generate(int n) {
		return OctetString.fromHex("34567");
	}
}
