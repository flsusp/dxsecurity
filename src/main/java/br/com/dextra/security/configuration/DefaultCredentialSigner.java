package br.com.dextra.security.configuration;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import br.com.dextra.security.Credential;
import br.com.dextra.security.utils.SignatureEncodingUtil;

public class DefaultCredentialSigner implements CredentialSigner {

    public String sign(final Credential data, final CertificateRepository certificateRepository) {
        final String authData = data.toString();

        final PrivateKeySpec privateKeySpec = certificateRepository.getPrivateKey();

        final String signature = sign(authData, privateKeySpec.getPrivateKey());
        if (!verify(data, signature, certificateRepository)) {
            throw new RuntimeException("Missed public and private keys.");
        }

        data.setKeyId(privateKeySpec.getKeyId());

        return signature;
    }

    public boolean verify(final Credential credential, final String signature,
            final CertificateRepository certificateRepository) {
        final PublicKey publicKey = certificateRepository.getPublicKeyFor(credential.getProvider(),
                credential.getKeyId());
        return verify(credential.toString(), signature, publicKey);
    }

    public boolean verify(final String token, final String signature, final PublicKey publicKey) {
        try {
            final Signature sig = Signature.getInstance("SHA1withDSA");
            sig.initVerify(publicKey);
            sig.update(token.getBytes());
            return sig.verify(SignatureEncodingUtil.decode(signature));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public String sign(final String data, final PrivateKey privateKey) {
        try {
            final Signature sig = Signature.getInstance("SHA1withDSA");
            sig.initSign(privateKey);
            sig.update(data.getBytes());
            final byte[] signature = sig.sign();

            return new String(SignatureEncodingUtil.encode(signature));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
