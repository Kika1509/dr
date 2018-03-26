package net.kapsch.kmc.api.service.mikey;

import com.google.zxing.common.BitArray;

import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.bouncycastle.util.Arrays;
import net.kapsch.kms.api.util.Utils;

public class PayloadGeneralExtensionDataUnitTest {

	@Test
	public void testEncodingDecoding() throws Exception {
		byte[] mcpttGroupId = ("mcpttgroupid@example.com").getBytes();
		byte[] activationTime = ("testTime").getBytes();
		byte[] text = ("testText").getBytes();

		PayloadGeneralExtensionData data1 = new PayloadGeneralExtensionData(mcpttGroupId,
				activationTime, text);

		BitArray encoded = data1.getEncoded();

		byte[] encodedBytes = Utils.getBytesFromBits(encoded);

		PayloadGeneralExtensionData data2 = PayloadGeneralExtensionData
				.decode(encodedBytes);

		Arrays.areEqual(data1.getActivationTime(), data2.getActivationTime());
		Assert.assertEquals(data1.getMcpttGroupId(), data2.getMcpttGroupId());
		Assert.assertEquals(data1.getText(), data2.getText());
		Arrays.areEqual(data1.getRandomPadding(), data2.getRandomPadding());
		Assert.assertEquals(data1.getReserved(), data2.getReserved());
		Assert.assertEquals(data1.getStatus(), data2.getStatus());
		Assert.assertEquals(data1.getEncoded(), data2.getEncoded());
	}
}
