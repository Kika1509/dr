package net.kapsch.kmc.api.service;

import java.util.Base64;

import org.bouncycastle.util.encoders.Hex;

public class KeyPair {

	/**
	 * Key for distribution (GMK, PCK, XKP, MSCCK, ...)
	 */
	private byte[] key;

	/**
	 * Key identifier associate with key above (GMK-ID, PCK-ID, XKP-ID, MSCCK-ID, ...)
	 */
	private int keyIdentifier;

	public KeyPair(byte[] key, int keyIdentifier) {
		this.key = key;
		this.keyIdentifier = keyIdentifier;
	}

	public String getKeyString() {
		return Base64.getEncoder().encodeToString(this.key);
	}

	public byte[] getKey() {
		return this.key;
	}

	public void setKey(byte[] key) {
		this.key = key;
	}

	public int getKeyIdentifier() {
		return this.keyIdentifier;
	}

	public void setKeyIdentifier(int keyIdentifier) {
		this.keyIdentifier = keyIdentifier;
	}

	@Override
	public String toString() {
		return "KeyPair{" + "key=" + new String(Hex.encode(key)) + ", keyIdentifier="
				+ keyIdentifier + '}';
	}
}
