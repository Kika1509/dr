package net.kapsch.kms.api.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import com.google.common.io.ByteStreams;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;
import org.xmlunit.builder.DiffBuilder;
import org.xmlunit.diff.Diff;
import org.xmlunit.util.Nodes;

import net.kapsch.kms.api.encryption.trk.TrkEncryption;
import net.kapsch.kms.api.encryption.trk.TrkResponse;

public class TrkEncryptionUnitTest {

	private String kmsKeyProvResponse;
	private String kmsInitResponse;
	private TrkEncryption trkEncryption;

	private static boolean assertXmlEqual(String expected, String actual, String[] diff)
			throws Exception {
		final Diff documentDiff = DiffBuilder.compare(expected).withTest(actual)
				.ignoreComments().ignoreWhitespace()
				.withNodeFilter(n -> !(n instanceof Element && Arrays.asList(diff)
						.contains(Nodes.getQName(n).getLocalPart())))
				.build();
		System.out.println(documentDiff.toString());
		return !documentDiff.hasDifferences();
	}

	private String getXmlData(String path) throws IOException {
		InputStream resourceAsStream = this.getClass().getResourceAsStream(path);
		byte[] data = ByteStreams.toByteArray(resourceAsStream);
		return new String(data);
	}

	@Before
	public void setup() throws IOException {
		this.kmsKeyProvResponse = getXmlData("/xml/KMSKeyProvExample.xml");
		this.kmsInitResponse = getXmlData("/xml/KMSInitExample.xml");
		this.trkEncryption = new TrkEncryption();
	}

	@Test
	public void testTrkEncryptionKeyProv() throws Exception {
		byte[] trk = Hex.decode(Base64.getDecoder().decode(
				"MDAwMTAyMDMwNDA1MDYwNzA4MDkwQTBCMEMwRDBFMEYxMDExMTIxMzE0MTUxNjE3MTgxOTFBMUIxQzFEMUUxRg=="));
		String encrypted = this.trkEncryption.applyKeyProvSecurityExtension(
				this.kmsKeyProvResponse, trk, Optional.empty(), "cip:mcptt1@op1.com");

		System.out.println(encrypted);

		TrkResponse decrypted = this.trkEncryption.resolveSecurityExtension(encrypted,
				trk, false);

		System.out.println(decrypted.getResponse());

		Assert.assertTrue(assertXmlEqual(this.kmsKeyProvResponse, decrypted.getResponse(),
				new String[] { "NewTransportKey" }));
	}

	@Test
	public void testTrkEncryptionKeyProvWithNewTrk() throws Exception {
		byte[] trk = Hex.decode(Base64.getDecoder().decode(
				"MDAwMTAyMDMwNDA1MDYwNzA4MDkwQTBCMEMwRDBFMEYxMDExMTIxMzE0MTUxNjE3MTgxOTFBMUIxQzFEMUUxRg=="));
		String encrypted = this.trkEncryption.applyKeyProvSecurityExtension(
				this.kmsKeyProvResponse, trk, Optional.ofNullable(trk),
				"cip:mcptt1@op1.com");

		System.out.println(encrypted);

		TrkResponse decrypted = this.trkEncryption.resolveSecurityExtension(encrypted,
				trk, true);

		System.out.println(decrypted.getResponse());

		Assert.assertTrue(assertXmlEqual(this.kmsKeyProvResponse, decrypted.getResponse(),
				new String[] { "NewTransportKey" }));
	}

	@Test
	public void testTrkEncryptionInit() throws Exception {
		byte[] trk = Hex.decode(Base64.getDecoder().decode(
				"MDAwMTAyMDMwNDA1MDYwNzA4MDkwQTBCMEMwRDBFMEYxMDExMTIxMzE0MTUxNjE3MTgxOTFBMUIxQzFEMUUxRg=="));
		String encrypted = this.trkEncryption.applyInitSecurityExtension(
				this.kmsInitResponse, trk, Optional.empty(), "cip:mcptt1@op1.com");

		System.out.println(encrypted);

		TrkResponse decrypted = this.trkEncryption.resolveSecurityExtension(encrypted,
				trk, false);

		System.out.println(decrypted.getResponse());

		Assert.assertTrue(assertXmlEqual(this.kmsInitResponse, decrypted.getResponse(),
				new String[] { "NewTransportKey" }));
	}

	@Test
	public void testTrkEncryptionInitWithNewTrk() throws Exception {
		byte[] trk = Hex.decode(Base64.getDecoder().decode(
				"MDAwMTAyMDMwNDA1MDYwNzA4MDkwQTBCMEMwRDBFMEYxMDExMTIxMzE0MTUxNjE3MTgxOTFBMUIxQzFEMUUxRg=="));
		byte[] newTrk = Hex.decode(Base64.getDecoder().decode(
				"QUFBMTAyMDMwNDA1MDYwNzA4MDkwQTBCMEMwRDBFMEYxMDExMTIxMzE0MTUxNjE3MTgxOTFBMUIxQzFEMUFBQQ=="));
		String encrypted = this.trkEncryption.applyInitSecurityExtension(
				this.kmsInitResponse, trk, Optional.ofNullable(newTrk),
				"cip:mcptt1@op1.com");

		System.out.println(encrypted);

		TrkResponse decrypted = this.trkEncryption.resolveSecurityExtension(encrypted,
				trk, true);

		System.out.println(decrypted.getResponse());

		Assert.assertTrue(assertXmlEqual(this.kmsInitResponse, decrypted.getResponse(),
				new String[] { "NewTransportKey" }));
	}

}
