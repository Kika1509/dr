package net.kapsch.kmc.api.service.mikey;

import java.util.Arrays;

import com.google.zxing.common.BitArray;

import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kmc.api.service.mikey.tables.GeneralExtensionType;
import net.kapsch.kmc.api.service.mikey.tables.NextPayload;

public class PayloadGeneralExtensionUnitTest {

	@Test
	public void testContructor() {
		byte[] data = ("testData").getBytes();

		PayloadGeneralExtension extension1 = new PayloadGeneralExtension();
		extension1.setData(data);

		PayloadGeneralExtension extension2 = new PayloadGeneralExtension(data);

		PayloadGeneralExtension extension3 = new PayloadGeneralExtension(NextPayload.SIGN,
				new byte[16], GeneralExtensionType.VENDOR_ID, (short) data.length, data);

		Assert.assertEquals(extension1.getData(), extension2.getData());
		Assert.assertEquals(extension1.getData(), extension3.getData());

		Assert.assertEquals(extension1.getLength(), extension2.getLength());
		Assert.assertEquals(extension1.getLength(), extension3.getLength());

		Assert.assertEquals(extension1.getType(), extension2.getType());
		Assert.assertEquals(extension1.getType(), extension3.getType());

		Assert.assertEquals(extension1.nextPayload, extension2.nextPayload);
		Assert.assertEquals(extension1.nextPayload, extension3.nextPayload);

		Assert.assertEquals(extension1.payloadType, extension2.payloadType);
		Assert.assertEquals(extension1.payloadType, extension3.payloadType);
	}

	@Test
	public void testEncodingDecoding() {
		byte[] data = ("testData").getBytes();

		PayloadGeneralExtension extension1 = new PayloadGeneralExtension(data);

		BitArray encoded = extension1.getEncoded();

		int size = encoded.getSizeInBytes();
		byte[] encodedBytes = new byte[size];
		encoded.toBytes(0, encodedBytes, 0, size);

		PayloadGeneralExtension extension2 = PayloadGeneralExtension.decode(encodedBytes);

		Assert.assertEquals(extension1.getType(), extension2.getType());
		Assert.assertEquals(extension1.getLength(), extension2.getLength());
		Arrays.equals(extension1.getData(), extension2.getData());
		Arrays.equals(extension1.getIv(), extension2.getIv());
		Assert.assertEquals(extension1.payloadType, extension2.payloadType);
		Assert.assertEquals(extension1.nextPayload, extension2.nextPayload);
		Assert.assertEquals(extension1.toString(), extension2.toString());
	}
}
