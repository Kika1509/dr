package net.kapsch.kmc.api.service.authorization;

import java.io.IOException;
import java.util.Base64;

import okhttp3.Request;
import okhttp3.Response;

import org.apache.commons.lang3.RandomStringUtils;

public final class Util {

	private static final int DEF_SIZE = 6;

	private Util() {
	}

	/**
	 * Generate random string of default size.
	 *
	 * @return generated state for authorize query parameter
	 */
	public static String generateStateParameter() {
		return Base64.getEncoder().encodeToString(
				RandomStringUtils.randomAlphanumeric(DEF_SIZE).getBytes());
	}

	public static void printRequest(Request request, String description) {
		System.out.println("\nREQUEST: " + description);
		System.out.println(request.method() + " " + request.url());
		System.out.println(request.headers());
	}

	public static void printResponse(Response response, String body) throws IOException {
		System.out.println("RESPONSE: " + response.code() + " " + response.message());
		System.out.println(response.headers());
		System.out.println(body);
	}

	public static void printResponse(Response response) throws IOException {
		System.out.println("RESPONSE: " + response.code() + " " + response.message());
		System.out.println(response.headers());
		System.out.println(response.body().string());
	}

}
