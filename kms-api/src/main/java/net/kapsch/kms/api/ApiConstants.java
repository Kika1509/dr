package net.kapsch.kms.api;

import java.nio.charset.Charset;

public final class ApiConstants {

	public static final String DEFAULT_CHARSET_NAME = "UTF-8";
	public static final Charset DEFAULT_CHARSET = Charset.forName(DEFAULT_CHARSET_NAME);

	private ApiConstants() {
	}
}
