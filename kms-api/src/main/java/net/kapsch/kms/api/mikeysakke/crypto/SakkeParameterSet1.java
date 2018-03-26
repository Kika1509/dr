package net.kapsch.kms.api.mikeysakke.crypto;

import java.math.BigInteger;

import net.kapsch.kms.api.bouncycastle.crypto.Digest;
import net.kapsch.kms.api.bouncycastle.crypto.digests.SHA256Digest;
import net.kapsch.kms.api.bouncycastle.math.ec.ECConstants;
import net.kapsch.kms.api.bouncycastle.math.ec.ECCurve;
import net.kapsch.kms.api.bouncycastle.math.ec.ECFieldElement;
import net.kapsch.kms.api.bouncycastle.math.ec.ECPoint;

/**
 * Describes a parameter set for MIKEY-SAKKE encryption using the SAKKE cryptosystem (RFC
 * 6508). Includes additional calculated information for performance. See RFC 6509 section
 * 2.1.1 paragraph 1 and RFC 6508 section 2.1, 2.3 for more details.
 */
public class SakkeParameterSet1 extends SakkeParameterSet {

	/**
	 * The identifier used for this parameter set.
	 */
	private static final int PARAMETER_SET_IDENTIFIER = 1;

	/**
	 * A prime number which is the order of the finite field F_p.
	 */
	private static final BigInteger p = new BigInteger("997ABB1F0A563FDA65C61198DAD0657A"
			+ "416C0CE19CB48261BE9AE358B3E01A2E" + "F40AAB27E2FC0F1B228730D531A59CB0"
			+ "E791B39FF7C88A19356D27F4A666A6D0" + "E26C6487326B4CD4512AC5CD65681CE1"
			+ "B6AFF4A831852A82A7CF3C521C3C09AA" + "9F94D6AF56971F1FFCE3E82389857DB0"
			+ "80C5DF10AC7ACE87666D807AFEA85FEB", 16);

	/**
	 * The length of prime number stored in bytes.
	 */
	private static final int P_LENGTH_BYTES = 128;

	/**
	 * An odd prime that divides p + 1.
	 */
	private static final BigInteger q = new BigInteger("265EAEC7C2958FF69971846636B4195E"
			+ "905B0338672D20986FA6B8D62CF8068B" + "BD02AAC9F8BF03C6C8A1CC354C69672C"
			+ "39E46CE7FDF222864D5B49FD2999A9B4" + "389B1921CC9AD335144AB173595A0738"
			+ "6DABFD2A0C614AA0A9F3CF14870F026A" + "A7E535ABD5A5C7C7FF38FA08E2615F6C"
			+ "203177C42B1EB3A1D99B601EBFAA17FB", 16);

	/**
	 * The x coordinate of generator point P.
	 */
	private static final BigInteger Px = new BigInteger("53FC09EE332C29AD0A7990053ED9B52A"
			+ "2B1A2FD60AEC69C698B2F204B6FF7CBF" + "B5EDB6C0F6CE2308AB10DB9030B09E10"
			+ "43D5F22CDB9DFA55718BD9E7406CE890" + "9760AF765DD5BCCB337C86548B72F2E1"
			+ "A702C3397A60DE74A7C1514DBA66910D" + "D5CFB4CC80728D87EE9163A5B63F73EC"
			+ "80EC46C4967E0979880DC8ABEAE63895", 16);

	/**
	 * The y coordinate of generator point P.
	 */
	private static final BigInteger Py = new BigInteger("0A8249063F6009F1F9F1F0533634A135"
			+ "D3E82016029906963D778D821E141178" + "F5EA69F4654EC2B9E7F7F5E5F0DE55F6"
			+ "6B598CCF9A140B2E416CFF0CA9E032B9" + "70DAE117AD547C6CCAD696B5B7652FE0"
			+ "AC6F1E80164AA989492D979FC5A4D5F2" + "13515AD7E9CB99A980BDAD5AD5BB4636"
			+ "ADB9B5706A67DCDE75573FD71BEF16D7", 16);

	/**
	 * The elliptic curve defined over finite field F_p. The curve follows the equation
	 * y^2 = x^3 - 3 * x modulo p.
	 */
	private static final ECCurve curve = new ECCurve.Fp(p, ECConstants.THREE.negate(),
			ECConstants.ZERO);

	/**
	 * The point P in the elliptic curve E(F_p) that generates the cyclic subgroup of
	 * order q.
	 */
	private static final ECPoint pointP = new ECPoint.Fp(curve,
			new ECFieldElement.Fp(p, Px), new ECFieldElement.Fp(p, Py));

	/**
	 * The pre-calculated value of <P,P> (Tate-Lichtenbaum Pairing).
	 */
	private static final BigInteger g = new BigInteger("66FC2A432B6EA392148F15867D623068"
			+ "C6A87BD1FB94C41E27FABE658E015A87" + "371E94744C96FEDA449AE9563F8BC446"
			+ "CBFDA85D5D00EF577072DA8F541721BE" + "EE0FAED1828EAB90B99DFB0138C78433"
			+ "55DF0460B4A9FD74B4F1A32BCAFA1FFA" + "D682C033A7942BCCE3720F20B9B7B040"
			+ "3C8CAE87B7A0042ACDE0FAB36461EA46", 16);

	/**
	 * The hashing algorithm to use.
	 */
	private static final Digest hash = new SHA256Digest();

	/**
	 * The size of the symmetric keys in bits to be exchanged by SAKKE.
	 */
	private static final int N = 128;

	/**
	 * The size of the symmetric keys in bytes to be exchanged by SAKKE.
	 */
	private static final int NBYTES = 16;

	/**
	 * The length of variable R (which is a point on elliptic curve E) when extracted from
	 * the SAKKE encapsulated data. See RFC 6508 section 4 (Points on E) and section 6.2.2
	 * for more details. An elliptic point should be stored in the form 0x04 || x' || y'
	 * where the length of the coordinated L = Ceiling(lg(p)/8) = size in p in bytes.
	 * Therefore the expected length should be (2 * LengthInBytes(p) ) + 1
	 */
	private static final int R_LENGTH_BYTES = 257;

	/**
	 * The expected length of the SAKKE encapsulated data. See RFC 6508 section 4
	 * (Encapsulated Data) for more details. The length should be ( 2 * LengthInBytes(p) )
	 * + LengthInBytes(n) + 1.
	 */
	private static final int ENC_DATA_LENGTH_BYTES = 273;

	public int parameterSetIdentifer() {
		return PARAMETER_SET_IDENTIFIER;
	}

	public BigInteger p() {
		return p;
	}

	public int pLengthBytes() {
		return P_LENGTH_BYTES;
	}

	public BigInteger q() {
		return q;
	}

	public ECPoint pointP() {
		return pointP;
	}

	public ECCurve curve() {
		return curve;
	}

	public BigInteger g() {
		return g;
	}

	public Digest hash() {
		return hash;
	}

	public int n() {
		return N;
	}

	public int nBytes() {
		return NBYTES;
	}

	public int rLengthBytes() {
		return R_LENGTH_BYTES;
	}

	public int encDataLengthBytes() {
		return ENC_DATA_LENGTH_BYTES;
	}
}
