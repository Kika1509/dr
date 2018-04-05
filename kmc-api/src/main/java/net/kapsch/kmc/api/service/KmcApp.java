package net.kapsch.kmc.api.service;


public final class KmcApp {

	public ApiService apiService;

	public KmcApp() {
	}

	public static void main(String[] args) throws Exception {

		new CmdApi(args);
	}

	public Client init(String accessToken, String mcpttId) {
		this.apiService = new ApiService(accessToken);
		return new Client(mcpttId, this.apiService);

	}

}
