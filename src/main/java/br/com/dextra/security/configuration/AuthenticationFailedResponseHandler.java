package br.com.dextra.security.configuration;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.dextra.security.exceptions.AuthenticationFailedException;

public interface AuthenticationFailedResponseHandler<E extends AuthenticationFailedException> {

    void sendResponse(E e, HttpServletRequest request, HttpServletResponse response) throws IOException;
}
