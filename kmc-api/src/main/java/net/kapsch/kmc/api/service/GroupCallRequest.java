package net.kapsch.kmc.api.service;

import net.kapsch.kmc.api.service.mikey.MikeySakkeIMessage;

public class GroupCallRequest {

	private KeyPair keyPair;
	private MikeySakkeIMessage mikeySakkeIMessage;
	private byte[] mcpttGroupId;
	private byte[] activationTime;
	private byte[] text;

	public GroupCallRequest(KeyPair keyPair, MikeySakkeIMessage mikeySakkeIMessage,
			byte[] mcpttGroupId, byte[] activationTime, byte[] text) {
		this.keyPair = keyPair;
		this.mikeySakkeIMessage = mikeySakkeIMessage;
		this.mcpttGroupId = mcpttGroupId;
		this.activationTime = activationTime;
		this.text = text;
	}

	public KeyPair getKeyPair() {
		return this.keyPair;
	}

	public MikeySakkeIMessage getMikeySakkeIMessage() {
		return this.mikeySakkeIMessage;
	}

	public byte[] getMcpttGroupId() {
		return this.mcpttGroupId;
	}

	public byte[] getActivationTime() {
		return this.activationTime;
	}

	public byte[] getText() {
		return this.text;
	}
}
