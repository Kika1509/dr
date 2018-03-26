import java.math.BigInteger;

import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;
import net.kapsch.kms.api.mikeysakke.crypto.Sakke;
import net.kapsch.kms.api.mikeysakke.crypto.SakkeParameterSet;
import net.kapsch.kms.api.mikeysakke.utils.OctetString;

public final class KmsApiApp {

	private KmsApiApp() {
	}

	public static void main(String[] args) {
		testMultiply();
	}

	public static void testMultiply() {
		SakkeParameterSet params = Sakke.getParamSet(1);

		final ECPoint ecPoint1 = params.pointP();

		BigInteger b1 = new BigInteger(
				"2789376488548812070156192170260787664739940774639260363318645432050278728845125221258249533544340228767679422302288016229850155791526387241433277147656752",
				10);

		final long time1 = System.currentTimeMillis();
		final ECPoint result1 = ecPoint1.multiply(b1);
		final long time2 = System.currentTimeMillis();

		OctetString result1Os = new OctetString(result1.getEncoded());
		System.out.println("time: " + (time2 - time1));
		System.out.println("result1Os: " + result1Os);
	}
}
