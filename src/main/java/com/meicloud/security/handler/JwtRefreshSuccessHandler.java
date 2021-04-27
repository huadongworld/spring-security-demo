package com.meicloud.security.handler;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.meicloud.security.config.JwtAuthenticationToken;
import com.meicloud.security.config.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * JWT刷新成功处理器
 *
 * @author HuaDong
 * @since 2021/4/26 21:36
 */
public class JwtRefreshSuccessHandler implements AuthenticationSuccessHandler{

	private SecurityConfig securityConfig;

	public JwtRefreshSuccessHandler(SecurityConfig securityConfig) {
		this.securityConfig = securityConfig;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
										Authentication authentication) throws IOException, ServletException {

		DecodedJWT jwt = ((JwtAuthenticationToken) authentication).getToken();
		boolean shouldRefresh = shouldTokenRefresh(jwt.getIssuedAt());

		if (shouldRefresh) {
			Algorithm algorithm = Algorithm.HMAC256(securityConfig.getTokenEncryptSalt());
			Date expiredDate = new Date(System.currentTimeMillis() + securityConfig.getTokenExpireTimeInSecond() * 1000);
			// 重新生成一个JWT返回给客户端
			String token = ((JwtAuthenticationToken) authentication).getJwtUserLoginDTO().sign(algorithm, expiredDate);
			response.setHeader(securityConfig.getTokenName(), token);
		}
	}
	
	protected boolean shouldTokenRefresh(Date issueAt){
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(securityConfig.getTokenRefreshIntervalInSecond()).isAfter(issueTime);
    }

}
