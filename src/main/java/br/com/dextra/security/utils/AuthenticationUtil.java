package br.com.dextra.security.utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import br.com.dextra.security.Credential;
import br.com.dextra.security.configuration.CertificateRepository;
import br.com.dextra.security.configuration.PrivateKeySpec;

public class AuthenticationUtil {

    public static String sign(final Credential data, final CertificateRepository certificateRepository) {
        final String authData = data.toString();

        final PrivateKeySpec privateKeySpec = certificateRepository.getPrivateKey();

        final String signature = sign(authData, privateKeySpec.getPrivateKey());
        if (!verify(data, signature, certificateRepository)) {
            throw new RuntimeException("Missed public and private keys.");
        }

        data.setKeyId(privateKeySpec.getKeyId());

        return signature;
    }

    public static boolean verify(Credential credential, String signature, CertificateRepository certificateRepository) {
        PublicKey publicKey = certificateRepository.getPublicKeyFor(credential.getProvider(), credential.getKeyId());
        return verify(credential.toString(), signature, publicKey);
    }

    public static boolean verify(String token, String signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("SHA1withDSA");
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

    public static String sign(String data, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance("SHA1withDSA");
            sig.initSign(privateKey);
            sig.update(data.getBytes());
            byte[] signature = sig.sign();

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
