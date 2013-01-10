package br.com.dextra.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.dextra.security.configuration.Configuration;
import br.com.dextra.security.exceptions.ExpiredAuthTokenException;
import br.com.dextra.security.exceptions.InvalidAuthTokenException;
import br.com.dextra.security.exceptions.TimestampParsingException;
import br.com.dextra.security.utils.AuthenticationUtil;

public class AuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    private static final String AUTH_REQUEST_PARAMETER = "auth";

    private Configuration configuration;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        process((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    protected void process(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        final String token = extractAuthTokenFrom(request);

        if (token == null) {
            sendError(request, response);
            return;
        }

        Credential credential;
        try {
            credential = processAndValidate(token);
        } catch (InvalidAuthTokenException e) {
            logger.warn("Invalid authentication token received.", e);
            configuration.getCookieManager().expireCookies(request, response);
            sendError(request, response);
            return;
        } catch (ExpiredAuthTokenException e) {
            logger.warn("Invalid authentication token received.", e);
            configuration.getCookieManager().expireCookies(request, response);
            sendExpiryError(request, response);
            return;
        } catch (Exception e) {
            e.printStackTrace();
            logger.warn("Error while processing the received authentication token : " + token, e);
            configuration.getCookieManager().expireCookies(request, response);
            sendError(request, response);
            return;
        }

        try {
            if (mustRenew(credential)) {
                configuration.getCookieManager().expireCookies(request, response);
                credential = renew(credential, request, response);
            }
        } catch (Exception e) {
            logger.warn("Error while processing the received authentication token : " + token, e);
            sendError(request, response);
            return;
        }

        try {
            CredentialHolder.register(credential);
            chain.doFilter(request, response);
        } finally {
            if (CredentialHolder.get() == null) {
                configuration.getCookieManager().expireCookies(request, response);
            }
            CredentialHolder.deregister();
        }
    }

    protected Credential renew(Credential credential, final HttpServletRequest request,
            final HttpServletResponse response) throws ParseException {
        credential = credential.renew();

        final String signature = AuthenticationUtil.sign(credential, configuration.getCertificateRepository());

        logger.info("Authentication token renew to : {}", credential);

        createAuthCookie(credential, signature, request, response);

        return credential;
    }

    protected void createAuthCookie(final Credential credential, final String signature, final HttpServletRequest req,
            final HttpServletResponse resp) {
        final String value = configuration.getTokenManager().generateToken(credential.toString(), signature);
        configuration.getCookieManager().createAuthCookie(value, req, resp, configuration.getCookieExpiryTimeout());
    }

    protected boolean mustRenew(Credential auth) {
        final long today = getToday().getTime();
        final long timeout = configuration.getRenewTimeout();
        final long time = auth.getTimestamp().getTime();
        return today - timeout > time;
    }

    protected Date getToday() {
        return new Date();
    }

    protected boolean expired(Credential credential) {
        final long today = getToday().getTime();
        final long timeout = configuration.getExpiryTimeout();
        final long time = credential.getTimestamp().getTime();
        return today - timeout > time;
    }

    protected Credential processAndValidate(final String token) throws InvalidAuthTokenException,
            ExpiredAuthTokenException {
        try {
            final Token parsedToken = configuration.getTokenManager().parseToken(token);

            final Credential credential = parseCredential(parsedToken);

            String provider = credential.getProvider();
            if (provider == null || !allowProvider(provider)) {
                throw new InvalidAuthTokenException(token);
            }

            if (expired(credential)) {
                throw new ExpiredAuthTokenException(credential);
            }

            if (AuthenticationUtil.verify(credential, parsedToken.getSignature(),
                    configuration.getCertificateRepository())) {
                return credential;
            } else {
                throw new InvalidAuthTokenException(credential);
            }
        } catch (TimestampParsingException e) {
            throw new InvalidAuthTokenException(e, token);
        }
    }

    protected Credential parseCredential(final Token parsedToken) {
        return Credential.parse(parsedToken.getCredential());
    }

    protected boolean allowProvider(final String provider) {
        return configuration.getAllowedProviders().contains(provider);
    }

    protected void sendError(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        configuration.getNotAuthenticatedHandler().sendResponse(req, resp);
    }

    protected void sendExpiryError(final HttpServletRequest req, final HttpServletResponse resp) throws IOException {
        configuration.getAuthenticationExpiredHandler().sendResponse(req, resp);
    }

    protected String decode(String token) {
        try {
            String decodedToken = URLDecoder.decode(token, "UTF-8");

            decodedToken = decodedToken.replaceAll(" ", "+");

            return decodedToken;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    protected String extractAuthTokenFrom(HttpServletRequest request) {
        String authToken = request.getParameter(AUTH_REQUEST_PARAMETER);
        if (authToken != null) {
            return decode(authToken);
        }

        return configuration.getCookieManager().extractAuthTokenFromCookie(request);
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
        String path = config.getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
        if (path == null) {
            path = config.getServletContext().getInitParameter(Configuration.CONFIGURATION_FILE_KEY);
        }

        this.configuration = Configuration.buildFromFile(getClassLoaderForConfiguration(), path);

        logger.info("Configuration loaded : {}", configuration);
    }

    protected ClassLoader getClassLoaderForConfiguration() {
        return getClass().getClassLoader();
    }

    @Override
    public void destroy() {
    }

    public Configuration getConfiguration() {
        return configuration;
    }

    public void setConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }
}
