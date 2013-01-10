package br.com.dextra.security.configuration;

import br.com.dextra.security.Token;

public interface TokenManager {

    String generateToken(String credential, String signature);

    Token parseToken(String token);
}
