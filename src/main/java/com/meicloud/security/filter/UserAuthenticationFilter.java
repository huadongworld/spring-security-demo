package com.meicloud.security.filter;

import com.alibaba.fastjson.JSON;
import com.meicloud.security.config.UserAuthenticationToken;
import com.meicloud.security.request.UserLoginRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 登录认证过滤器
 *
 * @author HuaDong
 * @since 2021/4/24 20:22
 */
public class UserAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public UserAuthenticationFilter() {
		super(new AntPathRequestMatcher("/user/login", "POST"));
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.getAuthenticationManager(), "AuthenticationManager must be specified");
		Assert.notNull(this.getSuccessHandler(), "AuthenticationSuccessHandler must be specified");
		Assert.notNull(this.getFailureHandler(), "AuthenticationFailureHandler must be specified");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		// TODO 这里的逻辑主要有两个作用，一个是进行初步的校验，一个是组装待认证的Token，举几个例子：

		// 1.微信授权登录：客户端会传过来一些加密串，这里逻辑主要解密这些加密串的数据获取unionId、openId、手机号以及用户昵称头像等基本信息，
		// 然后组装Token传给Provider进行下一步认证，如果这里报错直接就返回异常，不会进行下一步认证。

		// 2.手机短信验证码登录：这里主要验证短信验证码的正确性，然后组装Token传给Provider进行下一步认证，如果短信验证码错误直接抛异常

		// 3.账号密码图形验证码登录：这里主要验证图形验证码的正确性，然后组装Token传给Provider进行下一步认证，如果图形验证码错误直接抛异常

		// ...

		// =================================================== 示例 ===============================================

		String body = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
		String mobile = null, password = null, verifyCode = null;

		if(StringUtils.hasText(body)) {
			UserLoginRequest loginRequest = JSON.parseObject(body, UserLoginRequest.class);
			mobile = loginRequest.getMobile();
			password = loginRequest.getPassword();
			verifyCode = loginRequest.getVerifyCode();
		}

		// TODO 这里验证图形验证码 verifyCode 是否正确

		UserAuthenticationToken token = new UserAuthenticationToken(
				null, mobile, password);

		// 这里进行下一步认证，会走到我们定义的 UserAuthenticationProvider 中
		return this.getAuthenticationManager().authenticate(token);
	}

}
