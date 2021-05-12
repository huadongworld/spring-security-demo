package com.meicloud.security.handler;

import com.meicloud.security.exception.LoginAuthenticationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;

/**
 * 登录失败处理器
 *
 * @author HuaDong
 * @since 2021/4/24 21:08
 */
@Slf4j
public class HttpStatusLoginFailureHandler implements AuthenticationFailureHandler{

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		// TODO 走到这里说明认证流程失败了，会对异常信息做一个统一的处理，通过 response 写回到客户端

		// =================================================== 示例 ===============================================

		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");
		response.setCharacterEncoding(Charset.defaultCharset().displayName());

		if (exception instanceof LoginAuthenticationException) {
			LoginAuthenticationException e = (LoginAuthenticationException) exception;
			response.getWriter().print(e.toJSONString());
		} else {
			response.getWriter().print("{\"msg\": \"" + exception.getMessage() + "\"}");
		}

		log.error(exception.getMessage());
	}
}
