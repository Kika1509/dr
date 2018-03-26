package net.kapsch.kmc.api.service.mikey.utils;

import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.mikeysakke.utils.OctetString;
import net.kapsch.kms.api.util.Utils;

public class UtilsUnitTest {

	@Test
	public void xorBytesFromLeastSignificantTest() {
		byte[] x = OctetString.hexStringToByteArray("02000000000000");
		byte[] y = OctetString.hexStringToByteArray("0EC675AD498AFEEBB6960B3AABE6");
		byte[] wantedResult = OctetString
				.hexStringToByteArray("0EC675AD498AFEE9B6960B3AABE6");

		byte[] result = Utils.xorBytesFromLeastSignificant(x, y);

		Assert.assertEquals(new String(Hex.encode(wantedResult)),
				new String(Hex.encode(result)));
	}

	@Test
	public void concatenateByteArraysTest() throws IOException {
		byte[] x = OctetString.hexStringToByteArray("02");
		byte[] y = OctetString.hexStringToByteArray("000000000000");
		byte[] wantedResult = OctetString.hexStringToByteArray("02000000000000");

		byte[] result = Utils.concatenateByteArrays(x, y);

		Assert.assertEquals(new String(Hex.encode(wantedResult)),
				new String(Hex.encode(result)));

	}

	@Test
	public void intToByte() {
		int i = 2;
		byte[] iB = Utils.intToBytes(i);
		byte[] wantedIB = new byte[] { 00, 00, 00, 02 };

		Assert.assertEquals(new String(Hex.encode(wantedIB)), new String(Hex.encode(iB)));

	}

	@Test
	public void xorBytes() {
		byte[] x = OctetString.hexStringToByteArray(
				"47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573");
		byte[] y = OctetString.hexStringToByteArray(
				"b52c8fcf9255fe09dfcea673f01022b99e0752a3645a2f4f2bcbd40a30b5a5fe45fe4eaded400a5d1af363f90ce1493b");
		byte[] wantedResult = OctetString.hexStringToByteArray(
				"f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833");

		byte[] result = Utils.xorBytes(x, y);

		Assert.assertEquals(new String(Hex.encode(wantedResult)),
				new String(Hex.encode(result)));
	}

}
