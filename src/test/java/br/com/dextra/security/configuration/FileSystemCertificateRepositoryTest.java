package br.com.dextra.security.configuration;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import br.com.dextra.security.exceptions.InvalidKeyPathException;
import br.com.dextra.security.utils.GenerateKeysUtil;

public class FileSystemCertificateRepositoryTest {

    private static final String PROVIDER = "t";
    private File publicKeyFolder;
    private File privateKeyFile;

    @Before
    public void setupFoldersAndKeys() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        File privateKeyFolder = new File("/tmp/prv");
        if (!privateKeyFolder.exists()) {
            privateKeyFolder.mkdirs();
        }

        publicKeyFolder = new File("/tmp/pub");
        if (!publicKeyFolder.exists()) {
            publicKeyFolder.mkdirs();
        }

        GenerateKeysUtil.generateAndStoreKeys(privateKeyFolder.getAbsolutePath(), PROVIDER);
        new File(privateKeyFolder, "public.key").renameTo(new File(publicKeyFolder, PROVIDER));

        privateKeyFile = new File(privateKeyFolder, "private.key");
    }

    @After
    public void destroyFolders() {
        privateKeyFile.delete();
        privateKeyFile.getParentFile().delete();

        for (File file : publicKeyFolder.listFiles()) {
            file.delete();
        }
        publicKeyFolder.delete();
    }

    @Test
    public void testReadingKeys() {
        FileSystemCertificateRepository repo = new FileSystemCertificateRepository(privateKeyFile.getAbsolutePath(),
                publicKeyFolder.getAbsolutePath());
        assertNotNull(repo.getPrivateKey());
        assertNotNull(repo.getPublicKeyFor(PROVIDER, "default"));
    }

    @Test(expected = InvalidKeyPathException.class)
    public void testReadingUnexistentPublicKey() {
        FileSystemCertificateRepository repo = new FileSystemCertificateRepository(privateKeyFile.getAbsolutePath(),
                publicKeyFolder.getAbsolutePath());
        assertNotNull(repo.getPublicKeyFor("a", "default"));
    }

    @Test
    public void testReadingAndCachingKeys() {
        FileSystemCertificateRepository repo = new FileSystemCertificateRepository(privateKeyFile.getAbsolutePath(),
                publicKeyFolder.getAbsolutePath());

        PrivateKeySpec privateKey = repo.getPrivateKey();
        PublicKey publicKey = repo.getPublicKeyFor(PROVIDER, "default");
        assertNotNull(privateKey);
        assertNotNull(publicKey);

        PrivateKeySpec privateKey2 = repo.getPrivateKey();
        PublicKey publicKey2 = repo.getPublicKeyFor(PROVIDER, "default");
        assertNotNull(privateKey2);
        assertNotNull(publicKey2);

        assertSame(privateKey.getPrivateKey(), privateKey2.getPrivateKey());
        assertSame(publicKey, publicKey2);

        repo.clearCaches();

        PrivateKeySpec privateKey3 = repo.getPrivateKey();
        PublicKey publicKey3 = repo.getPublicKeyFor(PROVIDER, "default");
        assertNotNull(privateKey3);
        assertNotNull(publicKey3);

        assertNotSame(privateKey.getPrivateKey(), privateKey3.getPrivateKey());
        assertNotSame(publicKey, publicKey3);
    }
}
