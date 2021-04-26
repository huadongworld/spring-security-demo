package com.meicloud.security.handler;

import com.auth0.jwt.algorithms.Algorithm;
import com.meicloud.security.config.SecurityConfig;
import com.meicloud.security.dto.JwtUserLoginDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 登录成功处理器
 *
 * @author HuaDong
 * @since 2021/4/24 20:20
 */
@Slf4j
public class UserLoginSuccessHandler implements AuthenticationSuccessHandler{

	public static final String HEADER_SET_ACCESS_TOKEN = "Set-Access-Token";

	private SecurityConfig securityConfig;

	public UserLoginSuccessHandler(SecurityConfig securityConfig) {
		this.securityConfig = securityConfig;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		// TODO 走到这里说明认证成功，可以组装一些响应头的信息给到客户端，比如生成JWT令牌，或者加一些业务上的需求，比如登录送积分等等

		// =================================================== 示例 ===============================================

		// 这里的逻辑是生成JWT令牌（很多公司也会用Session），将生成的JWT返回给前端
		Date expiredDate = new Date(System.currentTimeMillis() + securityConfig.getTokenExpireTimeInSecond() * 1000);
		Algorithm algorithm = Algorithm.HMAC256(securityConfig.getTokenEncryptSalt());

		JwtUserLoginDTO jwtUserLoginDTO = (JwtUserLoginDTO) authentication.getPrincipal();
		String token = jwtUserLoginDTO.sign(algorithm, expiredDate);

		// 设置请求头，将JWT令牌以请求头的方式返回给前端
		response.addHeader(HEADER_SET_ACCESS_TOKEN, token);

	}
}
