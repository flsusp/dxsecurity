package br.com.dextra.security.configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

public class StringBase64CertificateRepository implements CertificateRepository {

	private final Base64 base64 = new Base64(true);
    private PrivateKey privateKey;
    private Map<String, PublicKey> publicKeys = new HashMap<String, PublicKey>();

    public void configurePrivateKey(String encoded) {
        try {
            byte[] encKey = decode(encoded);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    protected byte[] decode(String encoded) {
        return base64.decode(encoded.getBytes());
    }

    public void configurePublicKey(String provider, String encoded) {
        try {
            byte[] encKey = decode(encoded);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

            publicKeys.put(provider, publicKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PrivateKeySpec getPrivateKey() {
        return new PrivateKeySpec(privateKey, "default");
    }

    @Override
    public PublicKey getPublicKeyFor(String provider, String keyId) {
        return publicKeys.get(provider);
    }

    @Override
    public void clearCaches() {
    }

    @Override
    public boolean mustRenew(String keyId) {
        return false;
    }
}
