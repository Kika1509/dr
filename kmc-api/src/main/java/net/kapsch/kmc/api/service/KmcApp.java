package net.kapsch.kmc.api.service;

import net.kapsch.kmc.api.service.authorization.Authorization;

public final class KmcApp {

	public ApiService apiService;

	public KmcApp() {
	}

	public static void main(String[] args) throws Exception {

		new CmdApi(args);
	}

	public Client init(String kmsUrl, String kaasUrl, String kaasRedirectUrl,
			String accessToken, String sessionId, String clientId, String mcpttId) {

		if (accessToken != null) {
			this.apiService = new ApiService(kmsUrl, accessToken);

			return new Client(mcpttId, this.apiService);
		}
		else {
			Authorization authorization = new Authorization(sessionId, clientId, kaasUrl,
					kaasRedirectUrl);
			this.apiService = new ApiService(kmsUrl,
					authorization.getAccessToken().getAccessToken());

			return new Client(mcpttId, this.apiService, authorization);
		}
	}

}
