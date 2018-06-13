package net.kapsch.keyTransfer;

import java.net.SocketException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Server4kDriver {
	final static Logger logger = LoggerFactory.getLogger(Server4kDriver.class);

	public static void main(String[] args) throws SocketException{
		logger.info("Networking Tutorial v0.01");
		new Thread(new UdpServer4()).start();
	}
}
