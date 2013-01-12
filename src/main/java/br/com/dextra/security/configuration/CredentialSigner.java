package br.com.dextra.security.configuration;

import java.security.PrivateKey;
import java.security.PublicKey;

import br.com.dextra.security.Credential;

public interface CredentialSigner {

    String sign(Credential data, CertificateRepository certificateRepository);

    String sign(String data, PrivateKey privateKey);

    boolean verify(Credential credential, String signature, CertificateRepository certificateRepository);

    boolean verify(String token, String signature, PublicKey publicKey);
}
