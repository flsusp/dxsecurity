package br.com.dextra.security.configuration;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Comparator;
import java.util.Set;
import java.util.TreeSet;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DefaultCookieManager implements CookieManager {

	public static final String AUTH_COOKIE_NAME = "auth";

	private static final Comparator<? super Cookie> cookieComparator = new Comparator<Cookie>() {
		@Override
		public int compare(Cookie o1, Cookie o2) {
			return (-1) * o1.getName().compareTo(o2.getName());
		}
	};

	@Override
	public void createAuthCookie(String token, HttpServletRequest req, HttpServletResponse resp, int cookieExpiryTimeout) {
		Cookie authCookie = new Cookie(generateCookieName(), token);

		String path = generateCookiePath(req);

		authCookie.setPath(path);
		if (cookieExpiryTimeout > 0) {
			authCookie.setMaxAge(cookieExpiryTimeout);
		}

		resp.addCookie(authCookie);
	}

	protected String generateCookiePath(HttpServletRequest req) {
		String path = req.getContextPath();
		if (!path.endsWith("/")) {
			path += "/";
		}
		return path;
	}

	public String generateCookieName() {
		return AUTH_COOKIE_NAME + System.currentTimeMillis();
	}

	@Override
	public String extractAuthTokenFromCookie(HttpServletRequest request) {
		Set<Cookie> cookiesFound = new TreeSet<Cookie>(cookieComparator);

		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().startsWith(AUTH_COOKIE_NAME)) {
					cookiesFound.add(cookie);
				}
			}
		}

		if (cookiesFound.size() > 0) {
			Cookie cookie = cookiesFound.iterator().next();
			return decode(cookie.getValue());
		} else {
			return null;
		}
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

	@Override
	public void expireCookies(HttpServletRequest request, HttpServletResponse response) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().startsWith(AUTH_COOKIE_NAME)) {
					cookie.setMaxAge(0);
					cookie.setValue(null);
					cookie.setPath(generateCookiePath(request));
					response.addCookie(cookie);
				}
			}
		}
	}
}
