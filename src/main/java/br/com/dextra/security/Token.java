package br.com.dextra.security;

public class Token {

    private String credential;
    private String signature;

    public Token(String credential, String signature) {
        super();
        this.credential = credential;
        this.signature = signature;
    }

    public String getCredential() {
        return credential;
    }

    public String getSignature() {
        return signature;
    }
}
