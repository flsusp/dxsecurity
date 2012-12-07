package br.com.dextra.security.exceptions;

public class AuthenticationFailedException extends SecurityException {

    private static final long serialVersionUID = 4846962942986505063L;

    public AuthenticationFailedException() {
        super();
    }

    public AuthenticationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticationFailedException(String message) {
        super(message);
    }

    public AuthenticationFailedException(Throwable cause) {
        super(cause);
    }
}
