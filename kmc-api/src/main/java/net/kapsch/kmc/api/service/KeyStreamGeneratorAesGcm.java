package net.kapsch.kmc.api.service;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import net.kapsch.kms.api.encryption.aes.Aes;
import net.kapsch.kms.api.encryption.aes.AesCmEncryption;
import net.kapsch.kms.api.encryption.aes.AesGcmEncryption;
import net.kapsch.kms.api.util.Utils;

public class KeyStreamGeneratorAesGcm {

	private static final int SESSION_KEY_LENGTH = 16;

	/**
	 * In spec TS 133 179 - V13.4.0, section 7.6.1 says: "the session salt is 12 octets in
	 * length". But in the RFC 3711, section 5.1. Encryption: AES-CM and NULL says: "The
	 * default session salt key-length (n_s) SHALL be 112 bits. This implementation is
	 * referring to RFC 3711"
	 */
	private static final int SESSION_SALT_LENGTH = 14;
	private static final int IV_LENGTH = 16;

	/**
	 * Since this is the initial key derivation and the key derivation rate is equal to
	 * zero, the value of (index DIV key_derivation_rate) is zero (actually, a six-octet
	 * string of zeros).
	 */
	private static final byte[] INDEX_DIV_KDR = Hex.decode("000000000000");

	private static final byte[] SRTP_SESSION_KEY_LABEL = Hex.decode("00");
	private static final byte[] SRTP_SESSION_SALT_LABEL = Hex.decode("02");

	private static final byte[] SRTCP_SESSION_KEY_LABEL = Hex.decode("03");
	private static final byte[] SRTCP_SESSION_SALT_LABEL = Hex.decode("05");

	private final byte[] defaultSessionKeyLabel;
	private final byte[] defaultSessionSaltLabel;

	private byte[] sessionKey;
	private byte[] sessionSalt;

	private int counter;
	private byte[] keystream;

	public KeyStreamGeneratorAesGcm(byte[] masterKey, byte[] masterSalt,
			SrtpProtocol protocol) throws Exception {
		this.counter = 0;
		this.keystream = new byte[0];
		if (protocol.equals(SrtpProtocol.SRTP)) {
			this.defaultSessionKeyLabel = SRTP_SESSION_KEY_LABEL;
			this.defaultSessionSaltLabel = SRTP_SESSION_SALT_LABEL;
		}
		else {
			this.defaultSessionKeyLabel = SRTCP_SESSION_KEY_LABEL;
			this.defaultSessionSaltLabel = SRTCP_SESSION_SALT_LABEL;
		}

		generateSessionKeys(masterKey, masterSalt);
	}

	/**
	 * Generation of keystream. Every time this method is called, next keystream is
	 * generated.
	 *
	 * NOTE: encrypting with 00000000000000000000000000000000 because that way keystream
	 * want be changed after XOR in encryption, See KeyStreamGeneratorAesGcmUnitTest.claas
	 * keyStreamNotChangeTest() and keyStreamChangeTest() methods
	 *
	 * @param ssrc - ssrc
	 * @param packetIndex - packet index
	 *
	 * @throws Exception - throws Exception
	 */
	public void generateNextKeyStream(byte[] ssrc, byte[] packetIndex) throws Exception {

		byte[] iv = calculateIV(ssrc, packetIndex);
		byte[] plaintext = Hex.decode("00000000000000000000000000000000");

		byte[] cypherAndTag = AesGcmEncryption.encrypt(plaintext,
				Aes.getSecretKey(this.sessionKey), addCounter(iv), null);

		byte[] currentKeystream = Arrays.copyOfRange(cypherAndTag, 0, plaintext.length);

		this.keystream = Utils.concatenateByteArrays(this.keystream, currentKeystream);
	}

	private byte[] addCounter(byte[] iv) {
		BigInteger bigCounter = BigInteger.valueOf(this.counter)
				.mod(BigInteger.valueOf(2).pow(128));
		BigInteger result = new BigInteger(iv).add(bigCounter);
		this.counter++;

		return result.toByteArray();
	}

	/**
	 * The 128-bit integer value IV SHALL be defined by the SSRC, the SRTP packet index i,
	 * and the SRTP session salting key k_s, as below.
	 *
	 * IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
	 *
	 * Each of the three terms in the XOR-sum above is padded with as many leading zeros
	 * as needed to make the operation well-defined, considered as a 128-bit value.
	 *
	 * @param ssrc - ssrc
	 * @param i - packet index
	 *
	 * @return - iv
	 *
	 * @throws IOException - throws IOException
	 */
	private byte[] calculateIV(byte[] ssrc, byte[] i) throws IOException {
		BigInteger ekp16 = BigInteger.valueOf(2).pow(16);
		BigInteger ekp64 = BigInteger.valueOf(2).pow(64);

		BigInteger bigSalt = new BigInteger(this.sessionSalt).multiply(ekp16);
		BigInteger bigSsrc = new BigInteger(ssrc).multiply(ekp64);
		BigInteger bigI = new BigInteger(i).multiply(ekp16);

		return addPadding(bigSalt).xor(addPadding(bigSsrc)).xor(addPadding(bigI))
				.toByteArray();
	}

	private BigInteger addPadding(BigInteger bigInteger) throws IOException {
		byte[] bytes = bigInteger.toByteArray();
		if (bytes.length < IV_LENGTH) {
			SecureRandom random = new SecureRandom();
			byte[] randBytes = new byte[IV_LENGTH - bytes.length];
			random.nextBytes(randBytes);

			return new BigInteger(Utils.concatenateByteArrays(bytes, randBytes));
		}

		return bigInteger;
	}

	private void generateSessionKeys(byte[] masterKey, byte[] masterSalt)
			throws Exception {
		// generation of Session Key from PRF
		byte[] x = Utils.xorBytesFromLeastSignificant(
				Utils.concatenateByteArrays(this.defaultSessionKeyLabel, INDEX_DIV_KDR),
				masterSalt);
		this.sessionKey = srtpPrf(masterKey, x);

		if (this.sessionKey.length != SESSION_KEY_LENGTH) {
			throw new Exception("Session Key should be " + SESSION_KEY_LENGTH * Byte.SIZE
					+ " bits long");
		}

		// generation of Session Salt from PRF
		x = Utils.xorBytesFromLeastSignificant(
				Utils.concatenateByteArrays(this.defaultSessionSaltLabel, INDEX_DIV_KDR),
				masterSalt);
		byte[] paddedSessionSalt = srtpPrf(masterKey, x);
		this.sessionSalt = removePadding(paddedSessionSalt, 4);

		if (this.sessionSalt.length != SESSION_SALT_LENGTH) {
			throw new Exception("Session Salt should be "
					+ SESSION_SALT_LENGTH * Byte.SIZE + " bits long");
		}
	}

	private byte[] removePadding(byte[] data, int paddingSize) {
		String stringData = Hex.toHexString(data);
		stringData = stringData.substring(0, stringData.length() - paddingSize);

		return Hex.decode(stringData);
	}

	private byte[] srtpPrf(byte[] masterKey, byte[] x) throws Exception {
		x = new BigInteger(x).multiply(BigInteger.valueOf(2).pow(16)).toByteArray();

		return AesCmEncryption.encrypt(masterKey, x);
	}

	public byte[] getKeystream() {
		return this.keystream;
	}

	public byte[] getSessionKey() {
		return this.sessionKey;
	}

	// NOTE: for testing purposes only
	public void setSessionKey(byte[] sessionKey) {
		this.sessionKey = sessionKey;
	}

	public byte[] getSessionSalt() {
		return this.sessionSalt;
	}

	// NOTE: for testing purposes only
	public void setSessionSalt(byte[] sessionSalt) {
		this.sessionSalt = sessionSalt;
	}
}
