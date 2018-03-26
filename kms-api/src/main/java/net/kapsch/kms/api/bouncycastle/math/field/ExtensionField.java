package net.kapsch.kms.api.bouncycastle.math.field;

public interface ExtensionField extends FiniteField {
	FiniteField getSubfield();

	int getDegree();
}
