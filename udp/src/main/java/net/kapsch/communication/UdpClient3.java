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
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UdpClient3 implements Runnable {
	final Logger logger = LoggerFactory.getLogger(UdpServer4.class);

	private BufferedReader inFromUser;
	private DatagramSocket clientSocket;
	private InetAddress IPAddress;

	/*
	 * Our byte arrays that we'll use to read in and send out to our UDP server
	 */
	private byte[] outData;
	private byte[] inData;
	private final static String TARGET_MCPTT_ID_4 = "test4@example.org";
	private final static String KMS_URI = "kms.example.org";
	private final static String MCPTT_GROUP_ID_3 = "test3@example.org";
	private final static String ACTIVATION_TIME = "activate";
	public static final String TEST3_ACCESS_TOKEN = "eyJraWQiOiJXeGplT3lZV2pwTXZUS3lTZTJvNlRnV01vM0lhalJWWXUyR2YxaVR5ZkpZIiwiYWxnIjoiUlMyNTYifQ.eyJtY3B0dF9pZCI6InRlc3QzQGV4YW1wbGUub3JnIiwic3ViIjoiYWRtaW4iLCJhdWQiOlsiaHR0cDpcL1wvbG9jYWxob3N0OjUyMjdcL2thYXMiLCJwdHQiLCJrbSIsImNtIiwiZ20iXSwic2NwIjpbIm9wZW5pZCIsIjNncHA6bWNwdHQ6cHR0X3NlcnZlciIsIjNncHA6bWNwdHQ6a2V5X21hbmFnZW1lbnRfc2VydmVyIiwiM2dwcDptY3B0dDpjb25maWdfbWFuYWdlbWVudF9zZXJ2ZXIiLCIzZ3BwOm1jcHR0Omdyb3VwX21hbmFnZW1lbnRfc2VydmVyIl0sIm5iZiI6MTUxMTI3MTk1NywiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjUyMjdcL2thYXMiLCJleHAiOjE4MjY2MzE5NTcsImlhdCI6MTUxMTI3MTk1NywianRpIjoiMjQzMzA4ZWItNWZjNi00MWM0LWJmNDItNDNmZTNjMjM0OTBkIiwiY2lkIjoiZGUyYmNmZjItNzQxZi00NTE0LThiMDEtMDcxOTg3NjU5ZjNlIn0.Ei9sZL3PwsNCpWg8CockTE3XL50FeMk5sSthnHQHcIQvMEp16aVKcIwrlhGRtzZht3DNRIifkw6SRataPRhOdOGO4mxLZJs0jry7QQfYlmPRxc1paBqTeTjT3C-mK86j9YspdsRtmo6P4eAhr4VXnrySUemd7udRtCe_82cjNbWSLyuOVg4CwGfr8eh20nxU0wAjJShXDFj_BU6fUaLfrGg4U4wQ3aw04QHRjiQu9pwYiDe8aTXOZ4HAqrdhFAivhzl4mB7QJQICfp7Khe80pj1SZbiCRixUM8dw34iVX6zZgE8uX-0Ozg5DobpN14DGTCq_7WATVhD1tXO-djfQ4A";

	private ApiService apiService = new ApiService(TEST3_ACCESS_TOKEN);
	private Client client = new Client(MCPTT_GROUP_ID_3, apiService);

	/*
	 * Our Client constructor which instantiates our clientSocket
	 * and get's our IPAddress
	 */
	public UdpClient3() throws SocketException, UnknownHostException{
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
		 * Start a while loop that will run until we kill the program, this will continuously
		 * poll for user input and send it to the server.
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
				 * First we read in the users input from the console.
				 */
				System.out.print("> ");
				String sentence = inFromUser.readLine();
				//outData = sentence.getBytes();

				/*
				 * Next we create a datagram packet which will allow us send our message back to our datagram server
				 */
				//TODO: encrypt outData and make DatagramPacket from encryptedOutData
				OctetString gmkEncData = new OctetString();
				int gmkId = KeyUtils.generateKeyIdentifier(PurposeTag.GMK);
				OctetString gmk = Sakke.generateSharedSecretAndSED(gmkEncData,
						this.client.getUid(TARGET_MCPTT_ID_4.getBytes(), KMS_URI.getBytes()),
						domainKeys.getSakkeParameterSetIndex(),
						domainKeys.getKmsPublicKey(), new RandomGeneratorImpl());
				MikeySakkeIMessage iMessage = this.client.generateGroupCallMikeyMessage(gmk.getOctets(),
						gmkId, gmkEncData, TARGET_MCPTT_ID_4, KMS_URI, KMS_URI,
						MCPTT_GROUP_ID_3.getBytes(), ACTIVATION_TIME.getBytes(), sentence.getBytes());
				outData = iMessage.getEncoded();
				System.out.println(outData.length);
				System.out.println(Hex.encode(outData).length);
				System.out.println(new String(Hex.encode(outData)));



				DatagramPacket out = new DatagramPacket(outData, outData.length, IPAddress, 10000);
				clientSocket.send(out);

				/*
				 * Once we've sent our message we create a second datagram packet which will
				 * let us receive a response.
				 */
				DatagramPacket in = new DatagramPacket(inData, inData.length);
				clientSocket.receive(in);

				/*
				 * Finally we log the response from the server using log4j
				 */
				String modifiedSentence = new String(in.getData());
				logger.info("Server >" + modifiedSentence);

			} catch (IOException e) {
				/*
				 * Here we need to capture any exceptions thrown by our application
				 */
				logger.error("Exception Thrown: " + e.getLocalizedMessage());
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
