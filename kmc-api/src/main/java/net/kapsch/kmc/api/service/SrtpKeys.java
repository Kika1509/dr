package net.kapsch.kmc.api.service;

public class SrtpKeys {
	private byte[] srtpMaster;
	private byte[] srtpSalt;
	private int mki;

	public SrtpKeys(byte[] srtpMaster, byte[] srtpSalt, int mki) {
		this.srtpMaster = srtpMaster;
		this.srtpSalt = srtpSalt;
		this.mki = mki;
	}

	public byte[] getSrtpMaster() {
		return this.srtpMaster;
	}

	public byte[] getSrtpSalt() {
		return this.srtpSalt;
	}

	public int getMki() {
		return this.mki;
	}
}
