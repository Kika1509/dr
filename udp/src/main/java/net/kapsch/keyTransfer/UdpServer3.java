package net.kapsch.keyTransfer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import net.kapsch.kmc.api.service.ApiService;
import net.kapsch.kmc.api.service.Client;
import net.kapsch.kmc.api.service.GroupCallRequest;
import net.kapsch.kmc.api.service.mikey.MikeySakkeIMessage;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class UdpServer3 implements Runnable {
	final static Logger logger = LoggerFactory.getLogger(UdpServer3.class);
	public static final String TEST3_ACCESS_TOKEN = "eyJraWQiOiJXeGplT3lZV2pwTXZUS3lTZTJvNlRnV01vM0lhalJWWXUyR2YxaVR5ZkpZIiwiYWxnIjoiUlMyNTYifQ.eyJtY3B0dF9pZCI6InRlc3QzQGV4YW1wbGUub3JnIiwic3ViIjoiYWRtaW4iLCJhdWQiOlsiaHR0cDpcL1wvbG9jYWxob3N0OjUyMjdcL2thYXMiLCJwdHQiLCJrbSIsImNtIiwiZ20iXSwic2NwIjpbIm9wZW5pZCIsIjNncHA6bWNwdHQ6cHR0X3NlcnZlciIsIjNncHA6bWNwdHQ6a2V5X21hbmFnZW1lbnRfc2VydmVyIiwiM2dwcDptY3B0dDpjb25maWdfbWFuYWdlbWVudF9zZXJ2ZXIiLCIzZ3BwOm1jcHR0Omdyb3VwX21hbmFnZW1lbnRfc2VydmVyIl0sIm5iZiI6MTUxMTI3MTk1NywiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjUyMjdcL2thYXMiLCJleHAiOjE4MjY2MzE5NTcsImlhdCI6MTUxMTI3MTk1NywianRpIjoiMjQzMzA4ZWItNWZjNi00MWM0LWJmNDItNDNmZTNjMjM0OTBkIiwiY2lkIjoiZGUyYmNmZjItNzQxZi00NTE0LThiMDEtMDcxOTg3NjU5ZjNlIn0.Ei9sZL3PwsNCpWg8CockTE3XL50FeMk5sSthnHQHcIQvMEp16aVKcIwrlhGRtzZht3DNRIifkw6SRataPRhOdOGO4mxLZJs0jry7QQfYlmPRxc1paBqTeTjT3C-mK86j9YspdsRtmo6P4eAhr4VXnrySUemd7udRtCe_82cjNbWSLyuOVg4CwGfr8eh20nxU0wAjJShXDFj_BU6fUaLfrGg4U4wQ3aw04QHRjiQu9pwYiDe8aTXOZ4HAqrdhFAivhzl4mB7QJQICfp7Khe80pj1SZbiCRixUM8dw34iVX6zZgE8uX-0Ozg5DobpN14DGTCq_7WATVhD1tXO-djfQ4A";
	private final static String MCPTT_GROUP_ID_3 = "test3@example.org";

	private ApiService apiService = new ApiService(TEST3_ACCESS_TOKEN);
	private Client client = new Client(MCPTT_GROUP_ID_3, apiService);

	private DatagramSocket serverSocket;

	private byte[] in;
	private byte[] out;

	/*
	 * Instantiate serverSocket
	 */
	public UdpServer3() throws SocketException{
		serverSocket = new DatagramSocket(10000);
	}

	public void run() {
		try {
			client.init();
		}
		catch (JAXBException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (XMLStreamException e) {
			e.printStackTrace();
		}
		while(true){
			try {
				in = new byte[1024];
				out = new byte[1024];

				/*
				 * Create our inbound datagram packet
				 */
				DatagramPacket receivedPacket = new DatagramPacket(in, in.length);
				serverSocket.receive(receivedPacket);

				/*
				 * Get the data from the packet we've just received and decrypt it
				 */
				byte[] encryptedText = receivedPacket.getData();
				byte[] cropped = Arrays.copyOfRange(encryptedText, 0, receivedPacket.getLength());
				MikeySakkeIMessage iMessage = MikeySakkeIMessage.decode(cropped);

				GroupCallRequest decrypted = this.client.processGroupKeyTransportMessage(iMessage);
				String text = decrypted.getKeyPair().toString();

				out = text.toUpperCase().getBytes();
				System.out.println("String Received: " + text.trim());

				/*
				 * Retrieve the IP Address and port number of the datagram packet
				 * we've just received
				 */
				InetAddress IPAddress = receivedPacket.getAddress();
				int port = receivedPacket.getPort();

				/*
				 * Create a DatagramPacket which will return our message back to the last system
				 * that we received from
				 */
				DatagramPacket sendPacket = new DatagramPacket(in, in.length, IPAddress, port);
				serverSocket.send(sendPacket);
			} catch (IOException e) {
				logger.info("Exception thrown: " + e.getLocalizedMessage());
			}
//			catch (MikeyException e) {
//				e.printStackTrace();
//			}
			catch (Exception e) {
				e.printStackTrace();
			}

		}
	}
}
