package br.com.dextra.security.configuration;

import java.security.PrivateKey;
import java.security.PublicKey;

import br.com.dextra.security.Credential;

public interface CredentialSigner {

	String sign(Credential data, CertificateRepository certificateRepository, SignatureEncoder signatureEncoder);

	String sign(String data, CertificateRepository certificateRepository, SignatureEncoder signatureEncoder);

	String sign(String data, PrivateKey privateKey, SignatureEncoder signatureEncoder);

	boolean verify(Credential credential, String signature, CertificateRepository certificateRepository,
			SignatureEncoder signatureEncoder);

	boolean verify(String token, String signature, PublicKey publicKey, SignatureEncoder signatureEncoder);
}
