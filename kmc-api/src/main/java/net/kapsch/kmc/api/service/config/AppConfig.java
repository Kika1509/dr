package net.kapsch.kmc.api.service.config;

import java.io.IOException;
import java.util.Properties;

public class AppConfig {

	private final static String CONFIG_PATH = "config/application.properties";
	private final static String TRK_ENABLED = "kmc.security.trk.enabled";
	private final static String TRK_KEY = "kmc.security.trk.key";
	private final static String TRK_KEY_GENERATE_NEW = "kmc.security.trk.key.generate.new";

	private Properties properties;

	public AppConfig() {
		this.properties = new Properties();
		try {
			this.properties.load(
					AppConfig.class.getClassLoader().getResourceAsStream(CONFIG_PATH));
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean isTrkEnabled() {
		return Boolean.parseBoolean(this.properties.getProperty(TRK_ENABLED));
	}

	public String getTrkKey() {
		return this.properties.getProperty(TRK_KEY);
	}

	public boolean generateNewTrk() {
		return Boolean.parseBoolean(this.properties.getProperty(TRK_KEY_GENERATE_NEW));
	}
}
