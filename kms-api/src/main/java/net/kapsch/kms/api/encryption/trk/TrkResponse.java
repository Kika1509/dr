package net.kapsch.kms.api.encryption.trk;

public class TrkResponse {

	private String response;
	private byte[] newTransportKey;

	public TrkResponse(String response, byte[] newTransportKey) {
		this.response = response;
		this.newTransportKey = newTransportKey;
	}

	public String getResponse() {
		return this.response;
	}

	public void setResponse(String response) {
		this.response = response;
	}

	public byte[] getNewTransportKey() {
		return this.newTransportKey;
	}

	public void setNewTransportKey(byte[] newTransportKey) {
		this.newTransportKey = newTransportKey;
	}
}
