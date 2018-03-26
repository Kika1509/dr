package net.kapsch.kmc.api.service.mikeysakke.utils;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import net.kapsch.kms.api.mikeysakke.utils.ProjFp;

public class ProjFpUnitTest {

	BigInteger realPart = new BigInteger("3", 10);
	BigInteger imagPart = new BigInteger("2", 10);
	BigInteger prime = new BigInteger("23", 10);

	@Test
	public void testSquare() {
		ProjFp result = new ProjFp(realPart, imagPart, prime);
		result = result.square();

		BigInteger rTest = (realPart.pow(2)).subtract((imagPart.pow(2)));
		BigInteger imTest = realPart.multiply(imagPart).shiftLeft(1);

		Assert.assertEquals(rTest, result.getX1());
		Assert.assertEquals(imTest, result.getX2());
	}

	@Test
	public void testMultiply() {
		ProjFp result = new ProjFp(realPart, imagPart, prime);
		BigInteger realPart2 = new BigInteger("5", 10);
		BigInteger imagPart2 = new BigInteger("4", 10);
		BigInteger prime2 = new BigInteger("29", 10);
		ProjFp secondCompelx = new ProjFp(realPart2, imagPart2, prime2);

		BigInteger rTest = (realPart.multiply(secondCompelx.getX1()))
				.subtract((imagPart.multiply(secondCompelx.getX2())));
		BigInteger imTest = (realPart.multiply(secondCompelx.getX2()))
				.add((imagPart.multiply(secondCompelx.getX1())));

		result = result.multiply(secondCompelx);

		Assert.assertEquals(rTest, result.getX1());
		Assert.assertEquals(imTest, result.getX2());
	}

	@Test
	public void testModPow() {
		ProjFp result = new ProjFp(realPart, imagPart, prime);
		BigInteger n = new BigInteger("3", 10);

		ProjFp rTest = new ProjFp(realPart, imagPart, prime);

		result = result.modPow(n);

		rTest = (rTest.multiply(rTest)).multiply(rTest);

		Assert.assertEquals(rTest.getX1(), result.getX1());
		Assert.assertEquals(rTest.getX2(), result.getX2());

	}

}
