package br.com.dextra.security.configuration;

import static br.com.dextra.security.utils.StringConcatUtil.concat;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.dextra.security.exceptions.AuthenticationFailedException;

public class RedirectResponseHandler implements ResponseHandler,
        AuthenticationFailedResponseHandler<AuthenticationFailedException> {

    private String path;

    public RedirectResponseHandler(String path) {
        super();
        if (path != null) {
            path = path.trim();
            if (path.length() > 0 && !path.startsWith("/")) {
                path = concat("/", path);
            }
        }
        this.path = path;
    }

    @Override
    public void sendResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(concat(request.getContextPath(), this.path));
    }

    @Override
    public void sendResponse(AuthenticationFailedException e, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        sendResponse(request, response);
    }
}
