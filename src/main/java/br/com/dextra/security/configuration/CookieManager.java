package br.com.dextra.security.configuration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface CookieManager {

	public void createAuthCookie(String token, HttpServletRequest req, HttpServletResponse resp, int cookieExpiryTimeout);

	public String extractAuthTokenFromCookie(HttpServletRequest request);

	public void expireCookies(HttpServletRequest request, HttpServletResponse response);
}
