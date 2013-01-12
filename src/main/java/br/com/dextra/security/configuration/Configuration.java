package br.com.dextra.security.configuration;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.dextra.security.exceptions.AuthenticationFailedException;
import br.com.dextra.security.exceptions.ConfigurationException;
import bsh.EvalError;
import bsh.Interpreter;

public class Configuration {

    public static final String CONFIGURATION_FILE_KEY = "security.configuration.bsh";

    private static final int DEFAULT_COOKIE_EXPIRY_TIMEOUT = -1;
    private static final int DEFAULT_RENEW_TIMEOUT = Integer.MAX_VALUE;
    private static final int DEFAULT_EXPIRY_TIMEOUT = Integer.MAX_VALUE;

    private CertificateRepository certificateRepository;
    private String myProvider;
    private Set<String> allowedProviders = new HashSet<String>();

    private ResponseHandler notAuthenticatedHandler;
    private ResponseHandler authenticationSuccessHandler;
    private ResponseHandler authenticationExpiredHanler;
    private Map<Class<? extends AuthenticationFailedException>, AuthenticationFailedResponseHandler<AuthenticationFailedException>> authenticationFailedHandlers = new HashMap<Class<? extends AuthenticationFailedException>, AuthenticationFailedResponseHandler<AuthenticationFailedException>>();
    private CookieManager cookieManager;
    private TokenManager tokenManager;
    private CredentialSigner credentialSigner;

    private int cookieExpiryTimeout = DEFAULT_COOKIE_EXPIRY_TIMEOUT;
    private long expiryTimeout = DEFAULT_EXPIRY_TIMEOUT;
    private long renewTimeout = DEFAULT_RENEW_TIMEOUT;

    public static Configuration buildFromFile(ClassLoader loader, String path) {
        try {
            Configuration configuration = new Configuration();

            Interpreter i = new Interpreter();
            i.set("configuration", configuration);

            InputStreamReader reader = new InputStreamReader(loader.getResourceAsStream(path));

            i.eval(reader);

            configuration.validate();

            return configuration;
        } catch (EvalError e) {
            throw new ConfigurationException(e);
        }
    }

    public void validate() {
        if (certificateRepository == null) {
            throw new ConfigurationException(
                    "A certificate repository is required for the correct setup of the authentication mechanism.");
        }
        if (myProvider == null) {
            throw new ConfigurationException(
                    "The name of the provider is required for the correct setup of the authentication mechanism.");
        }

        if (allowedProviders == null) {
            allowedProviders = new HashSet<String>();
        }

        if (notAuthenticatedHandler == null) {
            notAuthenticatedHandler = new ForbiddenResponseHandler();
        }
        if (authenticationFailedHandlers.isEmpty()) {
            authenticationFailedHandlers.put(AuthenticationFailedException.class, new ForbiddenResponseHandler());
        }
        if (authenticationExpiredHanler == null) {
            authenticationExpiredHanler = new ForbiddenResponseHandler();
        }
        if (authenticationSuccessHandler == null) {
            authenticationSuccessHandler = new WriteTokenOnResponseResponseHandler();
        }
    }

    public CertificateRepository getCertificateRepository() {
        return certificateRepository;
    }

    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    public String getMyProvider() {
        return myProvider;
    }

    public void setMyProvider(String myProvider) {
        this.myProvider = myProvider;
        this.getAllowedProviders().add(myProvider);
    }

    public Set<String> getAllowedProviders() {
        return allowedProviders;
    }

    public void setAllowedProviders(String... allowedProviders) {
        Set<String> set = new HashSet<String>();
        for (String allowedProvider : allowedProviders) {
            set.add(allowedProvider);
        }
        setAllowedProviders(set);
    }

    public void setAllowedProviders(Set<String> allowedProviders) {
        this.allowedProviders = new HashSet<String>();
        this.allowedProviders.addAll(allowedProviders);
    }

    public ResponseHandler getNotAuthenticatedHandler() {
        return notAuthenticatedHandler;
    }

    public void setNotAuthenticatedHandler(ResponseHandler notAuthenticatedHandler) {
        this.notAuthenticatedHandler = notAuthenticatedHandler;
    }

    public AuthenticationFailedResponseHandler<AuthenticationFailedException> getAuthenticationFailedHandlerFor(
            Class<? extends AuthenticationFailedException> klass) {
        for (Map.Entry<Class<? extends AuthenticationFailedException>, AuthenticationFailedResponseHandler<AuthenticationFailedException>> entry : this.authenticationFailedHandlers
                .entrySet()) {
            Class<? extends AuthenticationFailedException> keyKlass = entry.getKey();
            if (keyKlass.isAssignableFrom(klass)) {
                return entry.getValue();
            }
        }
        throw new ConfigurationException(
                "Authentication failed exception not mapped: "
                        + klass
                        + ". Please, see the Configuration.setAuthenticationFailedHandler(Class, AuthenticationFailedHandler) for more details.");
    }

    public void setAuthenticationFailedHandler(Class<? extends AuthenticationFailedException> klass,
            AuthenticationFailedResponseHandler<AuthenticationFailedException> handler) {
        authenticationFailedHandlers.put(klass, handler);
    }

    /**
     * This method will set the given response handler to all exceptions derived from
     * {@link AuthenticationAuthenticationFailedResponseHandler}.
     *
     * @deprecated Use {@link #setAuthenticationFailedHandler(Class, AuthenticationFailedResponseHandler)}
     */
    @Deprecated
    public void setAuthenticationFailedHandler(final ResponseHandler authenticationFailedHandler) {
        authenticationFailedHandlers.put(AuthenticationFailedException.class,
                new AuthenticationFailedResponseHandler<AuthenticationFailedException>() {

                    @Override
                    public void sendResponse(AuthenticationFailedException e, HttpServletRequest request,
                            HttpServletResponse response) throws IOException {
                        authenticationFailedHandler.sendResponse(request, response);
                    }
                });
    }

    public ResponseHandler getAuthenticationSuccessHandler() {
        return authenticationSuccessHandler;
    }

    public void setAuthenticationSuccessHandler(ResponseHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    public ResponseHandler getAuthenticationExpiredHandler() {
        return authenticationExpiredHanler;
    }

    public void setAuthenticationExpiredHandler(ResponseHandler authenticationExpiredHanler) {
        this.authenticationExpiredHanler = authenticationExpiredHanler;
    }

    public TokenManager getTokenManager() {
        if (tokenManager == null) {
            tokenManager = new Base64TokenManager();
        }
        return tokenManager;
    }

    public void setTokenManager(TokenManager tokenManager) {
        this.tokenManager = tokenManager;
    }

    public CredentialSigner getCredentialSigner() {
        if (credentialSigner == null) {
            credentialSigner = new DefaultCredentialSigner();
        }
        return credentialSigner;
    }

    public void setCredentialSigner(CredentialSigner credentialSigner) {
        this.credentialSigner = credentialSigner;
    }

    public CookieManager getCookieManager() {
        if (cookieManager == null) {
            cookieManager = new DefaultCookieManager();
        }
        return cookieManager;
    }

    public void setCookieManager(CookieManager cookieManager) {
        this.cookieManager = cookieManager;
    }

    public int getCookieExpiryTimeout() {
        return cookieExpiryTimeout;
    }

    public void setCookieExpiryTimeout(int cookieExpiryTimeout) {
        this.cookieExpiryTimeout = cookieExpiryTimeout;
    }

    public long getExpiryTimeout() {
        return expiryTimeout;
    }

    public void setExpiryTimeout(long expiryTimeout) {
        this.expiryTimeout = expiryTimeout;
    }

    public long getRenewTimeout() {
        return renewTimeout;
    }

    public void setRenewTimeout(long renewTimeout) {
        this.renewTimeout = renewTimeout;
    }

    public void addAllowedProvider(String provider) {
        this.allowedProviders.add(provider);
    }
}
