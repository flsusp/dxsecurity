package br.com.dextra.security.configuration;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.dextra.security.exceptions.AuthenticationFailedException;

public class ForbiddenResponseHandler implements ResponseHandler, AuthenticationFailedResponseHandler<AuthenticationFailedException> {

    public static final int HTTP_ERROR_CODE = 403;

    @Override
    public void sendResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendError(HTTP_ERROR_CODE);
    }

    @Override
    public void sendResponse(AuthenticationFailedException e, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        response.sendError(HTTP_ERROR_CODE);
    }
}
