package com.meicloud.security.provider;

import com.meicloud.security.config.JwtAuthenticationToken;
import com.meicloud.security.config.UnionidAuthenticationToken;
import com.meicloud.security.dto.MemberLoginDTO;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Unionid认证 Provider
 *
 * @author HuaDong
 * @since 2021/4/24 21:31
 */
public class UnionidAuthenticationProvider implements AuthenticationProvider {

	public UnionidAuthenticationProvider() {

	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		// TODO

		MemberLoginDTO memberLoginDTO = new MemberLoginDTO();

		return new JwtAuthenticationToken(memberLoginDTO, null, null);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(UnionidAuthenticationToken.class);
	}
}
