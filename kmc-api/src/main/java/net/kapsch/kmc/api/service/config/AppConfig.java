package net.kapsch.kmc.api.service.config;

import java.io.IOException;
import java.util.Properties;

public class AppConfig {

	private final static String CONFIG_PATH = "config/application.properties";

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
}
