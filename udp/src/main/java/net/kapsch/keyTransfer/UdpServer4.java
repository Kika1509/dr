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


public class UdpServer4 implements Runnable {
	final static Logger logger = LoggerFactory.getLogger(UdpServer4.class);
	public static final String TEST4_ACCESS_TOKEN = "";
	private final static String MCPTT_GROUP_ID_4 = "test4@example.org";

	private ApiService apiService = new ApiService(TEST4_ACCESS_TOKEN);
	private Client client = new Client(MCPTT_GROUP_ID_4, apiService);

	private DatagramSocket serverSocket;

	private byte[] in;
	private byte[] out;

	/*
	 * Instantiate serverSocket
	 */
	public UdpServer4() throws SocketException{
		serverSocket = new DatagramSocket(20000);
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
