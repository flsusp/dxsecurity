package br.com.dextra.security.configuration;

public interface SignatureEncoder {

    byte[] encode(byte[] signature);

    byte[] decode(String signature);
}
