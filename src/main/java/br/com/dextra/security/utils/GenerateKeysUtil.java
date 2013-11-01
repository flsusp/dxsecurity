package br.com.dextra.security.utils;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

import br.com.dextra.security.configuration.StringBase64CertificateRepository;

public class GenerateKeysUtil {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		generateAndStoreKeys("/tmp", "Test");
	}

	public static StringBase64CertificateRepository generateKeys(String provider) throws NoSuchAlgorithmException,
			NoSuchProviderException, IOException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();

		StringBase64CertificateRepository repo = new StringBase64CertificateRepository();
		repo.configurePrivateKey(new String(Base64.encodeBase64(pair.getPrivate().getEncoded())));
		repo.configurePublicKey(provider, new String(Base64.encodeBase64(pair.getPublic().getEncoded())));

		return repo;
	}

	public static void generateAndStoreKeys(String path, String provider) throws NoSuchAlgorithmException,
			NoSuchProviderException, IOException {
		StringBase64CertificateRepository repo = generateKeys(provider);

		store(repo.getPublicKeyFor(provider, null).getEncoded(), path + "/public.key");
		store(repo.getPrivateKey().getPrivateKey().getEncoded(), path + "/private.key");
	}

	private static void store(byte[] encoded, String path) throws IOException {
		FileOutputStream fos = new FileOutputStream(path);
		BufferedOutputStream bos = new BufferedOutputStream(fos);

		bos.write(encoded);

		bos.close();
		fos.close();
	}
}
