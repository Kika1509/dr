package net.kapsch.kms.api.encryption.aes;

import java.util.Arrays;

/**
 * Holder class that allows us to bundle ciphertext and IV together.
 */
public class CipherTextIvMac {
	private final byte[] cipherText;
	private final byte[] iv;
	private final byte[] mac;

	public byte[] getCipherText() {
		return this.cipherText;
	}

	public byte[] getIv() {
		return this.iv;
	}

	public byte[] getMac() {
		return this.mac;
	}

	/**
	 * Construct a new bundle of ciphertext and IV.
	 * @param c The ciphertext
	 * @param i The IV
	 * @param h The mac
	 */
	public CipherTextIvMac(byte[] c, byte[] i, byte[] h) {
		this.cipherText = new byte[c.length];
		System.arraycopy(c, 0, this.cipherText, 0, c.length);
		this.iv = new byte[i.length];
		System.arraycopy(i, 0, this.iv, 0, i.length);
		this.mac = new byte[h.length];
		System.arraycopy(h, 0, this.mac, 0, h.length);
	}

	/**
	 * Constructs a new bundle of ciphertext and IV from a string of the format
	 * <code>base64(iv):base64(ciphertext)</code>.
	 *
	 * @param base64IvAndCiphertext A string of the format <code>iv:ciphertext</code> The
	 * IV and ciphertext must each be base64-encoded.
	 */
	public CipherTextIvMac(String base64IvAndCiphertext) {
		String[] civArray = base64IvAndCiphertext.split(":");
		if (civArray.length != 3) {
			throw new IllegalArgumentException("Cannot parse iv:ciphertext:mac");
		}
		else {
			this.iv = Base64.DECODER.decode(civArray[0]);
			this.mac = Base64.DECODER.decode(civArray[1]);
			this.cipherText = Base64.DECODER.decode(civArray[2]);
		}
	}

	/**
	 * Concatinate the IV to the cipherText using array copy. This is used e.g. before
	 * computing mac.
	 * @param iv The IV to prepend
	 * @param cipherText the cipherText to append
	 * @return iv:cipherText, a new byte array.
	 */
	public static byte[] ivCipherConcat(byte[] iv, byte[] cipherText) {
		byte[] combined = new byte[iv.length + cipherText.length];
		System.arraycopy(iv, 0, combined, 0, iv.length);
		System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
		return combined;
	}

	/**
	 * Encodes this ciphertext, IV, mac as a string.
	 *
	 * @return base64(iv) : base64(mac) : base64(ciphertext). The iv and mac go first
	 * because they're fixed length.
	 */
	@Override
	public String toString() {
		String ivString = Base64.ENCODER.encodeToString(this.iv);
		String cipherTextString = Base64.ENCODER.encodeToString(this.cipherText);
		String macString = Base64.ENCODER.encodeToString(this.mac);
		return ivString + ":" + macString + ":" + cipherTextString;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(this.cipherText);
		result = prime * result + Arrays.hashCode(this.iv);
		result = prime * result + Arrays.hashCode(this.mac);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CipherTextIvMac other = (CipherTextIvMac) obj;
		if (!Arrays.equals(this.cipherText, other.cipherText)) {
			return false;
		}
		if (!Arrays.equals(this.iv, other.iv)) {
			return false;
		}
		if (!Arrays.equals(this.mac, other.mac)) {
			return false;
		}
		return true;
	}
}
