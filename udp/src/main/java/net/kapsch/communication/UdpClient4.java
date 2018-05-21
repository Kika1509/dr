package net.kapsch.communication;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import net.kapsch.kmc.api.service.ApiService;
import net.kapsch.kmc.api.service.Client;
import net.kapsch.kmc.api.service.DomainKeyData;
import net.kapsch.kmc.api.service.mikey.MikeySakkeIMessage;
import net.kapsch.kms.api.mikeysakke.PurposeTag;
import net.kapsch.kms.api.mikeysakke.crypto.Sakke;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.mikeysakke.utils.RandomGeneratorImpl;
import net.kapsch.kms.api.util.KeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UdpClient4 implements Runnable {
	final Logger logger = LoggerFactory.getLogger(UdpServer4.class);

	private BufferedReader inFromUser;
	private DatagramSocket clientSocket;
	private InetAddress IPAddress;

	private byte[] outData;
	private byte[] inData;
	private final static String TARGET_MCPTT_ID_3 = "test3@example.org";
	private final static String KMS_URI = "kms.example.org";
	private final static String MCPTT_GROUP_ID_4 = "test4@example.org";
	private final static String ACTIVATION_TIME = "activate";
	public static final String TEST3_ACCESS_TOKEN = "";

	private ApiService apiService = new ApiService(TEST3_ACCESS_TOKEN);
	private Client client = new Client(MCPTT_GROUP_ID_4, apiService);

	public UdpClient4() throws SocketException, UnknownHostException{
		clientSocket = new DatagramSocket();
		IPAddress = InetAddress.getByName("localhost");
		inFromUser = new BufferedReader(new InputStreamReader(System.in));
	}

	private void shutdown(){
		clientSocket.close();
	}

	public void run() {
		logger.info("Client Started, Listening for Input:");
		/*
		 * Continuously pull for user input and send it to the server.
		 */
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
				inData = new byte[1024];
				//outData = new byte[1024];
				DomainKeyData domainKeys = this.client.getDomainKeys();
				/*
				 * Read users input from the console.
				 */
				System.out.print("> ");
				String sentence = inFromUser.readLine();

				/*
				 * Encrypt data and create a datagram packet
				 */
				OctetString gmkEncData = new OctetString();
				int gmkId = KeyUtils.generateKeyIdentifier(PurposeTag.GMK);
				OctetString gmk = Sakke.generateSharedSecretAndSED(gmkEncData,
						this.client.getUid(TARGET_MCPTT_ID_3.getBytes(), KMS_URI.getBytes()),
						domainKeys.getSakkeParameterSetIndex(),
						domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());
				MikeySakkeIMessage iMessage = this.client.generateGroupCallMikeyMessage(gmk.getOctets(),
						gmkId, gmkEncData, TARGET_MCPTT_ID_3, KMS_URI, KMS_URI,
						MCPTT_GROUP_ID_4.getBytes(), ACTIVATION_TIME.getBytes(), sentence.getBytes());
				outData = iMessage.getEncoded();

				DatagramPacket out = new DatagramPacket(outData, outData.length, IPAddress, 10000);
				clientSocket.send(out);

				/*
				 * Datagram for response
				 */
				DatagramPacket in = new DatagramPacket(inData, inData.length);
				clientSocket.receive(in);

				/*
				 * Response log
				 */
				String modifiedSentence = new String(in.getData());
				logger.info("Server >" + modifiedSentence);

			} catch (IOException e) {
				logger.error("Exception Thrown: " + e.getLocalizedMessage());
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
