package net.kapsch.communication;

import java.net.SocketException;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientDriver {
	final static Logger logger = LoggerFactory.getLogger(ServerDriver.class);

	public static void main(String[] args) throws SocketException, UnknownHostException{
		logger.info("Starting Client...");
		new Thread(new UdpClient3()).start();
	}
}
