package net.kapsch.kmc.api.service.mikeysakke.utils;

import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.mikeysakke.utils.OctetString;

public class OctetStringUnitTest {

	@Test
	public void testOctetStringConstructor() {
		int expectedBytesLenght = 0;
		OctetString octetString = new OctetString();
		Assert.assertEquals(0, octetString.getOctets().length);

		expectedBytesLenght = 17;
		octetString = new OctetString(expectedBytesLenght);
		Assert.assertEquals(expectedBytesLenght, octetString.getOctets().length);

		expectedBytesLenght = 10;
		octetString = new OctetString(new byte[expectedBytesLenght]);
		Assert.assertEquals(expectedBytesLenght, octetString.getOctets().length);

		// todo ...
	}

	@Test
	public void testSubStringOK() {
		OctetString octetString = OctetString.fromAscii("testOctetString");
		int startIndex = 4;
		int length = 2;
		int expetcedSize = octetString.getOctets().length - startIndex;

		octetString = octetString.subString(startIndex);

		Assert.assertEquals(expetcedSize, octetString.getOctets().length);

		octetString = octetString.subString(startIndex, length);

		Assert.assertEquals(length, octetString.getOctets().length);
	}

	@Test(expected = NegativeArraySizeException.class)
	public void testSubStringNegativeSize() {
		OctetString octetString = OctetString.fromAscii("testOctetString");
		int startIndex = octetString.getOctets().length + 1;

		octetString.subString(startIndex);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSubStringOutsideTheRange() {
		OctetString octetString = OctetString.fromAscii("testOctetString");
		int startIndex = 4;
		int length = octetString.getOctets().length + 1;

		octetString.subString(startIndex, length);
	}

	@Test
	public void testEqualsAndHash() {
		OctetString a = new OctetString();
		OctetString b = new OctetString();

		Assert.assertTrue(a.equals(b));
		Assert.assertTrue(b.equals(a));
		Assert.assertEquals(a.hashCode(), b.hashCode());

		a = new OctetString(new byte[] { 1, 2, 3 });
		b = new OctetString(new byte[] { 1, 2, 3 });

		Assert.assertTrue(a.equals(b));
		Assert.assertTrue(b.equals(a));
		Assert.assertEquals(a.hashCode(), b.hashCode());

		a = new OctetString(new byte[] { 1, 2, 3, 4 });
		b = new OctetString(new byte[] { 1, 2, 3 });

		Assert.assertFalse(a.equals(b));
		Assert.assertFalse(b.equals(a));
		Assert.assertNotEquals(a.hashCode(), b.hashCode());
	}

	@Test
	public void testToAsciiToHex() {
		String hexString = "74657374"; // test - hex values
		String string = "test";
		byte[] bytes = new byte[] { 116, 101, 115, 116 }; // test - ascii dec values
		OctetString octetString = new OctetString(bytes);

		Assert.assertEquals(string, octetString.toAscii());
		Assert.assertEquals(hexString, octetString.toHex());
		Assert.assertEquals(hexString, octetString.toString());
	}

	@Test
	public void testFromAsciiFromHex() {
		String asciiString = "test";
		String hexString = "74657374"; // test - hex values

		OctetString fromHex = OctetString.fromHex(hexString);
		OctetString fromAscii = OctetString.fromAscii(asciiString);

		Assert.assertEquals(fromHex, fromAscii);
	}

	@Test
	public void testEmptyMethod() {
		byte[] bytes = null;
		OctetString octetString = new OctetString(bytes);
		Assert.assertTrue(octetString.empty());

		bytes = new byte[0];
		octetString = new OctetString(bytes);
		Assert.assertTrue(octetString.empty());

		bytes = new byte[1];
		octetString = new OctetString(bytes);
		Assert.assertFalse(octetString.empty());
	}

	@Test
	public void testAllZeroesMethod() {
		byte[] bytes = new byte[50];
		OctetString octetString = new OctetString(bytes);
		Assert.assertTrue(octetString.allZeroes());

		bytes[12] = 116;
		octetString = new OctetString(bytes);
		Assert.assertFalse(octetString.allZeroes());
	}

	@Test
	public void testAppendMethod() {
		String allString = "test";
		String firstPart = "te";
		String secondPart = "st";

		OctetString octetStringFirst = OctetString.fromAscii(firstPart);
		Assert.assertEquals(firstPart, octetStringFirst.toAscii());

		OctetString octetStringSecond = OctetString.fromAscii(secondPart);
		Assert.assertEquals(secondPart, octetStringSecond.toAscii());

		octetStringFirst.append(octetStringSecond);
		Assert.assertEquals(allString, octetStringFirst.toAscii());

		octetStringSecond.append(octetStringFirst);
		Assert.assertNotEquals(allString, octetStringSecond.toAscii());
	}

	@Test
	public void testappendNullTerminator() {
		String string = "test";
		int size = string.length();
		OctetString octetString = OctetString.fromAscii(string);

		Assert.assertEquals(size, octetString.size());

		octetString.appendNullTerminator();

		Assert.assertEquals(size + 1, octetString.size());
		Assert.assertEquals(0, octetString.getOctets()[octetString.size() - 1]);
	}

	@Test
	public void testSizeMethod() {
		String string = "test";
		int size = string.length();
		OctetString octetString = OctetString.fromAscii(string);

		Assert.assertEquals(size, octetString.getOctets().length);
		Assert.assertEquals(octetString.getOctets().length, octetString.size());
	}

}
