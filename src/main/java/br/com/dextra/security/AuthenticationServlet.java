package br.com.dextra.security;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.dextra.security.configuration.Configuration;
import br.com.dextra.security.exceptions.AuthenticationFailedException;

/**
 * The authentication servlet is responsible for validating the user credentials present on the
 * {@link HttpServletRequest}. The method that does this is {@link #authenticate(HttpServletRequest)}. If a
 * {@link Credential} is returned from this method a signed token is generated and returned to the client as a cookie.
 * After that, the {@link Configuration#getAuthenticationSuccessHandler()} is executed.
 *
 * If the authentication fail and the method {@link #authenticate(HttpServletRequest)} throws
 * {@link AuthenticationFailedException}, the {@link Configuration#getAuthenticationFailedHandler()} is executed.
 */
public abstract class AuthenticationServlet extends HttpServlet {

    private static final long serialVersionUID = 2l;

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServlet.class);
    private static final String CLEAR_CERTIFICATE_REPOSITORY_CACHE_KEY = "certificateRepository.clearCaches";

    protected Configuration configuration;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        startAuthentication(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        startAuthentication(req, resp);
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        String path = config.getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
        if (path == null) {
            path = config.getServletContext().getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
        }

        this.configuration = Configuration.buildFromFile(getClassLoaderForConfiguration(), path);

        logger.info("Configuration loaded : {}", configuration);

        super.init(config);
    }

    protected ClassLoader getClassLoaderForConfiguration() {
        return getClass().getClassLoader();
    }

    protected void startAuthentication(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        CredentialHolder.deregister();

        clearCachesIfRequestParameter(req);

        try {
            final Credential credential = authenticate(req);
            CredentialHolder.register(credential);

            final String signature = sign(credential);

            createAuthCookie(credential, signature, req, resp);

            sendSuccess(credential, req, resp);
        } catch (AuthenticationFailedException e) {
            logger.debug("Authentication failed.", e);
            sendError(e, req, resp);
        }
    }

    protected void createAuthCookie(final Credential credential, final String signature, final HttpServletRequest req,
            final HttpServletResponse resp) {
        final String value = configuration.getTokenManager().generateToken(credential.toString(), signature);
        configuration.getCookieManager().createAuthCookie(value, req, resp, configuration.getCookieExpiryTimeout());
    }

    protected void clearCachesIfRequestParameter(final HttpServletRequest req) {
        if (req.getParameter(CLEAR_CERTIFICATE_REPOSITORY_CACHE_KEY) != null) {
            configuration.getCertificateRepository().clearCaches();
        }
    }

    protected void sendError(final AuthenticationFailedException e, final HttpServletRequest req,
            final HttpServletResponse resp) throws IOException {
        configuration.getAuthenticationFailedHandlerFor(e.getClass()).sendResponse(e, req, resp);
    }

    protected void sendSuccess(final Credential credential, final HttpServletRequest req, final HttpServletResponse resp)
            throws IOException {
        configuration.getAuthenticationSuccessHandler().sendResponse(req, resp);
    }

    protected String sign(final Credential credential) {
        return configuration.getCredentialSigner().sign(credential, configuration.getCertificateRepository());
    }

    public Configuration getConfiguration() {
        return configuration;
    }

    public void setConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }

    /**
     * This method should be implemented to authenticate the user accordingly to the application's business rules. If
     * the authentication fail, this method should throw {@link AuthenticationFailedException}. If the authentication is
     * successful a {@link Credential} or a class that extends it should be returned.
     *
     * @param req
     *            The full HTTP request.
     * @return A valid {@link Credential}. It can be a class that extends {@link Credential}.
     * @throws AuthenticationFailedException
     *             If the authentication fail.
     */
    protected abstract Credential authenticate(final HttpServletRequest req) throws AuthenticationFailedException;
}
