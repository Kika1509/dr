package net.kapsch.kms.api.encryption.aes;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class AesKeyWrapWithPadding {

	private final static boolean WRAP = true;
	private final static boolean UNWRAP = false;

	private RFC5649WrapEngine wrapEngine;

	public AesKeyWrapWithPadding() {
		this.wrapEngine = new RFC5649WrapEngine(new AESEngine());
	}

	public byte[] wrap(byte[] kek, byte[] keyData) {
		this.wrapEngine.init(WRAP, new KeyParameter(kek));
		return this.wrapEngine.wrap(keyData, 0, keyData.length);
	}

	public byte[] unwrap(byte[] kek, byte[] keyData) throws InvalidCipherTextException {
		this.wrapEngine.init(UNWRAP, new KeyParameter(kek));
		return this.wrapEngine.unwrap(keyData, 0, keyData.length);
	}
}
