package net.kapsch.kmc.api.service.service;

import net.kapsch.kmc.api.service.exceptions.KmsServerException;
import net.kapsch.kmc.api.service.exceptions.KmsServerInternalException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;


public class DocumentService extends BaseService {

	private Request.Builder builder;

	private OkHttpClient client;

	public DocumentService(OkHttpClient client, Request.Builder builder) {
		this.client = client;
		this.builder = builder;
	}

	@Override
	public String get(String path) {
		Request request = builder.url(path).build();
		System.out.println(request.toString() + "\n");

		try (Response response = this.client.newCall(request).execute()) {
			if (response.code() == 404) {
				throw new KmsServerException("Entity with path: " + path + " doesn't exist.");
			}
			System.out.println(response.toString() + "\n");
			return response.body().string();
		}
		catch (KmsServerException e) {
			throw e;
		}
		catch (Exception e) {
			throw new KmsServerInternalException(e.getMessage(), e);
		}
	}

	@Override
	public String post(String xmlBody, String mediaType) {
		RequestBody body = RequestBody.create(MediaType.parse(mediaType), xmlBody);

		return makeRequest(builder.url("http://localhost:8080/example").post(body).build());
		//TODO: find out which path to use

	}

	private String makeRequest(Request request) {
		System.out.println(request.toString() + "\n");
		try (Response response = this.client.newCall(request).execute()) {
			if (response.code() != 200) {
				throw new KmsServerException("POST not successful");
			}
			System.out.println(response.toString() + "\n");
			return "Sent!";

		}
		catch (Exception e) {
			throw new KmsServerInternalException(e.getMessage(), e);
		}
	}

}
