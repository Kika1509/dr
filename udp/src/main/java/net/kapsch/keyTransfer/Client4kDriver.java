package net.kapsch.keyTransfer;

import java.net.SocketException;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Client4kDriver {
	final static Logger logger = LoggerFactory.getLogger(Server4kDriver.class);

	public static void main(String[] args) throws SocketException, UnknownHostException{
		logger.info("Starting Client...");
		new Thread(new UdpClient4()).start();
	}
}
