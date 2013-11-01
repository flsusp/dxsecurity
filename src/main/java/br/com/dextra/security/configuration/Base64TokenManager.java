package br.com.dextra.security.configuration;

import java.util.Iterator;

import br.com.dextra.security.Token;

import com.google.common.base.Joiner;
import com.google.common.base.Splitter;

public class Base64TokenManager implements TokenManager {

    protected final SignatureEncoder encoder = new Base64SignatureEncoder();

    @Override
    public String generateToken(String credential, String signature) {
        String s = Joiner.on('@').join(credential, signature);
        return new String(encoder.encode(s.getBytes()));
    }

    @Override
    public Token parseToken(String token) {
        String s = new String(encoder.decode(token));
        Iterator<String> i = Splitter.on('@').split(s).iterator();

        String credential = i.next();
        String signature = i.next();

        return new Token(credential, signature);
    }
}
