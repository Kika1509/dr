package net.kapsch.kms.api.encryption.trk;

import java.util.UUID;

import net.kapsch.kms.api.util.UUIDUtils;

public final class TrkUtil {

	private final static String TRK_NAME = "TRK";
	private final static String TRK_SUFFIX = "-" + TRK_NAME;

	private TrkUtil() {
	}

	public static String getSecretMetadataName() {
		return TRK_NAME;
	}

	public static String getSecretName(String mcpttId) {
		return mcpttId + TRK_SUFFIX;
	}

	public static UUID getSecretUuid(String mcpttId) {
		return UUIDUtils.nameUUIDFromBytes(getSecretName(mcpttId));
	}

	public static UUID getSecretOwnerUuid(String mcpttId) {
		return UUIDUtils.nameUUIDFromBytes(mcpttId);
	}
}
