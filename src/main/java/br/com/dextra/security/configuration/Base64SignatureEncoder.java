package br.com.dextra.security.configuration;

import org.apache.commons.codec.binary.Base64;

public class Base64SignatureEncoder implements SignatureEncoder {

    public byte[] encode(byte[] signature) {
        return Base64.encodeBase64(signature);
    }

    public byte[] decode(String signature) {
        return Base64.decodeBase64(signature.getBytes());
    }
}
