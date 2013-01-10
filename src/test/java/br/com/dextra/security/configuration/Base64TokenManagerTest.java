package br.com.dextra.security.configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import br.com.dextra.security.Token;

public class Base64TokenManagerTest {

    @Test
    public void testTokenGenerationAndParse() {
        TokenManager tokenManager = new Base64TokenManager();
        String token = tokenManager.generateToken("credential", "signature");

        assertNotNull(token);
        assertEquals("Y3JlZGVudGlhbEBzaWduYXR1cmU=", token);

        Token parsedToken = tokenManager.parseToken(token);

        assertEquals("credential", parsedToken.getCredential());
        assertEquals("signature", parsedToken.getSignature());
    }
}
