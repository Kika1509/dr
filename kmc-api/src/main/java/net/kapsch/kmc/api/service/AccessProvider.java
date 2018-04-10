package net.kapsch.kmc.api.service;

import okhttp3.Request;

public interface AccessProvider {
	Request.Builder getAccess(String accessProvider);
}
