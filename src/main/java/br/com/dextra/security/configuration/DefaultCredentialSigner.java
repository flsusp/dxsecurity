package br.com.dextra.security.configuration;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import br.com.dextra.security.Credential;

public class DefaultCredentialSigner implements CredentialSigner {

	public String sign(final Credential data, final CertificateRepository certificateRepository,
			final SignatureEncoder signatureEncoder) {
		final String authData = data.toString();

		final PrivateKeySpec privateKeySpec = certificateRepository.getPrivateKey();

		final String signature = sign(authData, privateKeySpec.getPrivateKey(), signatureEncoder);
		if (!verify(data, signature, certificateRepository, signatureEncoder)) {
			throw new RuntimeException("Missed public and private keys.");
		}

		data.setKeyId(privateKeySpec.getKeyId());

		return signature;
	}

	public boolean verify(final Credential credential, final String signature,
			final CertificateRepository certificateRepository, final SignatureEncoder signatureEncoder) {
		final PublicKey publicKey = certificateRepository.getPublicKeyFor(credential.getProvider(),
				credential.getKeyId());
		return verify(credential.toString(), signature, publicKey, signatureEncoder);
	}

	public boolean verify(final String token, final String signature, final PublicKey publicKey,
			final SignatureEncoder signatureEncoder) {
		try {
			final Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initVerify(publicKey);
			sig.update(token.getBytes());
			return sig.verify(signatureEncoder.decode(signature));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	public String sign(final String data, final PrivateKey privateKey, final SignatureEncoder signatureEncoder) {
		try {
			final Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initSign(privateKey);
			sig.update(data.getBytes());
			final byte[] signature = sig.sign();

			return new String(signatureEncoder.encode(signature));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String sign(String data, CertificateRepository certificateRepository, SignatureEncoder signatureEncoder) {
		return sign(data, certificateRepository.getPrivateKey().getPrivateKey(), signatureEncoder);
	}
}
