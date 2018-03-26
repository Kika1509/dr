package net.kapsch.kms.api.bouncycastle.math.field;

public interface PolynomialExtensionField extends ExtensionField {
	Polynomial getMinimalPolynomial();
}
