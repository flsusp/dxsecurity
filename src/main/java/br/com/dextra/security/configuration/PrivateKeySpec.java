package br.com.dextra.security.configuration;

import java.security.PrivateKey;

public class PrivateKeySpec {

    private PrivateKey privateKey;
    private String keyId;

    public PrivateKeySpec(PrivateKey privateKey, String keyId) {
        super();
        this.privateKey = privateKey;
        this.keyId = keyId;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getKeyId() {
        return keyId;
    }
}
