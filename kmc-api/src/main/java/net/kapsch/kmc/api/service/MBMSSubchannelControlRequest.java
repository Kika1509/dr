package net.kapsch.kmc.api.service;

import net.kapsch.kmc.api.service.mikey.MikeySakkeIMessage;

public class MBMSSubchannelControlRequest {

	private KeyPair keyPair;
	private MikeySakkeIMessage mikeySakkeIMessage;

	public MBMSSubchannelControlRequest(KeyPair keyPair, MikeySakkeIMessage mikeySakkeIMessage) {
		this.keyPair = keyPair;
		this.mikeySakkeIMessage = mikeySakkeIMessage;
	}

	public KeyPair getKeyPair() {
		return this.keyPair;
	}

	public MikeySakkeIMessage getMikeySakkeIMessage() {
		return this.mikeySakkeIMessage;
	}
}
