package br.com.dextra.security.configuration;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import br.com.dextra.security.Credential;
import br.com.dextra.security.CredentialHolder;

public class WriteTokenOnResponseResponseHandler implements ResponseHandler {

	private final Configuration config;

	public WriteTokenOnResponseResponseHandler(Configuration config) {
		this.config = config;
	}

	@Override
	public void sendResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
		Credential credential = CredentialHolder.get();

		response.getWriter().append(
				config.getTokenManager().generateToken(
						credential.toString(),
						config.getCredentialSigner().sign(credential, config.getCertificateRepository(),
								config.getSignatureEncoder())));
	}
}
