package net.kapsch.kms.api.util;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.kapsch.kms.api.mikeysakke.crypto.EccsiParameterSet;

public class MikeySakkeUid {
	private static final Logger log = LoggerFactory.getLogger(MikeySakkeUid.class);
	private static final String MIKEY_SAKKE_UID = "MIKEY-SAKKE-UID";
	private static final String FC = "0";

	protected MikeySakkeUid() {

	}

	public static String generateUid(String mcpttId, String kmsUri, int keyPeriodLength,
			int keyPeriodOffset, int currentKeyPeriodNo) {
		StringBuilder sb = new StringBuilder();
		sb.append(FC);
		sb.append(MIKEY_SAKKE_UID);
		sb.append(EncodingUtils.encodeLengthOf(MIKEY_SAKKE_UID));
		sb.append(mcpttId);
		sb.append(EncodingUtils.encodeLengthOf(mcpttId));
		sb.append(kmsUri);
		sb.append(EncodingUtils.encodeLengthOf(kmsUri));

		int size = EncodingUtils.octetSizeOf(keyPeriodLength);
		sb.append(EncodingUtils.encodeInteger(keyPeriodLength, size));
		sb.append(EncodingUtils.encodeLength(size));

		size = EncodingUtils.octetSizeOf(keyPeriodOffset);
		sb.append(EncodingUtils.encodeInteger(keyPeriodOffset, size));
		sb.append(EncodingUtils.encodeLength(size));

		size = EncodingUtils.octetSizeOf(currentKeyPeriodNo);
		sb.append(EncodingUtils.encodeInteger(currentKeyPeriodNo, size));
		sb.append(EncodingUtils.encodeLength(size));

		return hash(sb.toString());
	}

	private static String hash(String value) {
		log.debug("Hashing input string: {}", value);
		byte[] result = new byte[32];
		EccsiParameterSet.hash(value.getBytes(), value.length(), result);
		String hexBinary = DatatypeConverter.printHexBinary(result);
		log.debug("Hash output: {}", hexBinary);

		return hexBinary;
	}
}
