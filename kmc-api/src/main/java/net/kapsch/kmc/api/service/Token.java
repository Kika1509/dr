package net.kapsch.kmc.api.service;

import net.kapsch.kmc.api.service.service.BaseService;
import okhttp3.Request;

public class Token implements AccessProvider {
	@Override
	public Request.Builder getAccess(String accessProvider) {
		return new Request.Builder().header(BaseService.getAuthorizationHeader(), BaseService.getBearerPrefix() + accessProvider);
	}
}
