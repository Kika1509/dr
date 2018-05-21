package net.kapsch.communication;

import java.net.SocketException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Server3Driver {
	final static Logger logger = LoggerFactory.getLogger(Server3Driver.class);

	public static void main(String[] args) throws SocketException{
		logger.info("Networking Tutorial v0.01");
		new Thread(new UdpServer3()).start();
	}
}
