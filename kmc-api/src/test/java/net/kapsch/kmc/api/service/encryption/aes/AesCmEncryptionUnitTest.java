package net.kapsch.kmc.api.service.encryption.aes;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import net.kapsch.kms.api.encryption.aes.AesCmEncryption;

/**
 * RFC 3711, B.3. Key Derivation Test Vectors
 */
public class AesCmEncryptionUnitTest {

	@Test
	public void encryptCipherKeyTest() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] xAfterMultiple = Hex.decode("0EC675AD498AFEEBB6960B3AABE60000");
		byte[] wantedResult = Hex.decode("C61E7A93744F39EE10734AFE3FF7A087");

		byte[] cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);

		Arrays.areEqual(wantedResult, cipherKey);
	}

	@Test
	public void encryptCipherSaltTest() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] xAfterMultiple = Hex.decode("0EC675AD498AFEE9B6960B3AABE60000");
		byte[] wantedResult = Hex.decode("30CBBC08863D8C85D49DB34A9AE17AC6");

		byte[] cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);

		Arrays.areEqual(wantedResult, cipherKey);
	}

	@Test
	public void encryptAuthKeyTest() throws Exception {
		byte[] masterKey = Hex.decode("E1F97A0D3E018BE0D64FA32C06DE4139");
		byte[] xAfterMultiple = Hex.decode("0EC675AD498AFEEAB6960B3AABE60000");
		byte[] wantedResult = Hex.decode("CEBE321F6FF7716B6FD4AB49AF256A15");
		byte[] cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);
		Arrays.areEqual(wantedResult, cipherKey);

		xAfterMultiple = Hex.decode("0EC675AD498AFEEAB6960B3AABE60001");
		wantedResult = Hex.decode("6D38BAA48F0A0ACF3C34E2359E6CDBCE");
		cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);
		Arrays.areEqual(wantedResult, cipherKey);

		xAfterMultiple = Hex.decode("0EC675AD498AFEEAB6960B3AABE60002");
		wantedResult = Hex.decode("E049646C43D9327AD175578EF7227098");
		cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);
		Arrays.areEqual(wantedResult, cipherKey);

		xAfterMultiple = Hex.decode("0EC675AD498AFEEAB6960B3AABE60003");
		wantedResult = Hex.decode("6371C10C9A369AC2F94A8C5FBCDDDC25");
		cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);
		Arrays.areEqual(wantedResult, cipherKey);

		xAfterMultiple = Hex.decode("0EC675AD498AFEEAB6960B3AABE60004");
		wantedResult = Hex.decode("6D6E919A48B610EF17C2041E47403576");
		cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);
		Arrays.areEqual(wantedResult, cipherKey);

		xAfterMultiple = Hex.decode("0EC675AD498AFEEAB6960B3AABE60005");
		wantedResult = Hex.decode("6B68642C59BBFC2F34DB60DBDFB2");
		cipherKey = AesCmEncryption.encrypt(masterKey, xAfterMultiple);
		Arrays.areEqual(wantedResult, cipherKey);
	}
}
