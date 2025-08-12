package kmip

func (kwd KeyWrappingData) IsEmpty() bool {
	return kwd.WrappingMethod == 0 &&
		kwd.EncryptionKeyInformation.UniqueIdentifier == ""
}

// Keep KMIP 1.4 semantics on decode.
// If the client sent CRYPTOGRAPHIC_LENGTH equal to the *ciphertext* length (e.g., 320),
// and KeyWrappingData indicates NIST Key Wrap, fix it to the plaintext length.
func (kb *KeyBlock) AfterUnmarshalKMIP() {
	if kb.KeyWrappingData.IsEmpty() {
		return // plaintext path — nothing special to do
	}

	// Only correct for NIST Key Wrap (RFC 3394).
	// Adjust the enum name/path to your model if different.
	if kb.KeyWrappingData.EncryptionKeyInformation.CryptoParams.BlockCipherMode != BLOCK_MODE_NISTKeyWrap {
		return
	}

	ct := kb.Value.KeyMaterial
	if len(ct) < 16 || len(ct)%8 != 0 {
		// Not a valid AES-KW ciphertext, don't touch.
		return
	}

	// RFC 3394: ciphertext = plaintext + 8 bytes
	ptBits := int32((len(ct) - 8) * 8)

	// If the decoded value looks like it was set from ciphertext, correct it.
	// Only adjust when it clearly mismatches; otherwise leave sender's value as-is.
	if ptBits > 0 && kb.CryptographicLength != 0 && kb.CryptographicLength != ptBits {
		kb.CryptographicLength = ptBits
	}
}
