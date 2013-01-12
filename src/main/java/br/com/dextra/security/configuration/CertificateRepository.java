package br.com.dextra.security.configuration;

import java.security.PublicKey;

public interface CertificateRepository {

    public PrivateKeySpec getPrivateKey();

    public PublicKey getPublicKeyFor(String provider, String keyId);

    public boolean mustRenew(String keyId);

    public void clearCaches();
}
