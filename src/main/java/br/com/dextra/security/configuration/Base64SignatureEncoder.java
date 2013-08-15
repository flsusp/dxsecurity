package br.com.dextra.security.configuration;

import org.apache.commons.codec.binary.Base64;

public class Base64SignatureEncoder implements SignatureEncoder {

	private final Base64 base64 = new Base64(-1, new byte[0], true);

	public byte[] encode(byte[] signature) {
		return base64.encode(signature);
	}

	public byte[] decode(String signature) {
		return base64.decode(signature.getBytes());
	}
}
