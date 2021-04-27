package com.meicloud.security.provider;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.meicloud.security.config.JwtAuthenticationToken;
import com.meicloud.security.config.SecurityConfig;
import com.meicloud.security.dto.JwtUserLoginDTO;
import com.meicloud.security.exception.LoginAuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Calendar;

/**
 * JWT认证 Provider
 *
 * @author HuaDong
 * @since 2021/4/26 21:35
 */
public class JwtAuthenticationProvider implements AuthenticationProvider{

	private SecurityConfig securityConfig;

	public JwtAuthenticationProvider(SecurityConfig securityConfig) {
		this.securityConfig = securityConfig;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		DecodedJWT jwt = ((JwtAuthenticationToken) authentication).getToken();
		// 令牌过期
		if(jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
			throw LoginAuthenticationException.JWT_EXPIRED;
		}

		try {
			// 校验令牌的合法性
			Algorithm algorithm = Algorithm.HMAC256(securityConfig.getTokenEncryptSalt());
			JwtUserLoginDTO loginResultDTO = JwtUserLoginDTO.fromDecodeJWT(jwt, algorithm);
			return new JwtAuthenticationToken(loginResultDTO, jwt, null);
        } catch (Exception e) {
            throw new BadCredentialsException("JWT token verify fail", e);
        }
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(JwtAuthenticationToken.class);
	}

}
