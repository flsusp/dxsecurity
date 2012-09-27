package br.com.dextra.security.exceptions;

import static br.com.dextra.security.utils.StringConcatUtil.concat;
import br.com.dextra.security.Credential;

public class ExpiredAuthTokenException extends SecurityException {

	private static final long serialVersionUID = 9180746328888903346L;

	public ExpiredAuthTokenException(Credential authData) {
		super(concat("Expired auth token : ", authData));
	}
}
