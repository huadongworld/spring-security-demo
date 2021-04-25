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

		// TODO 这里主要进行一个数据库层面的认证，比如账号密码的正确性，比如该账号是否被拉黑有什么权限等，都认证成功之后会组装一个认证通过的 Token

		UnionidAuthenticationToken token = (UnionidAuthenticationToken) authentication;

		// 这个 memberId 应该是数据库根据手机号，或者账号查询出来的用户主键
		Long memberId = 100000000L;

		// 组装并返回认证成功的 Token
		MemberLoginDTO memberLoginDTO = new MemberLoginDTO(token.getUnionId(), token.getOpenId(), memberId, token.getMobile());

		// 这里认证成功返回之后会跑到成功处理器：UnionidLoginSuccessHandler
		// 只要整个认证（包括前面的校验）中有一个地方抛出异常都会调用失败处理器：HttpStatusLoginFailureHandler

		System.out.println("认证Provider...");

		return new JwtAuthenticationToken(memberLoginDTO, null, null);
	}

	/**
	 * 表示这个 Provider 支持认证的 Token（这里是 UnionidAuthenticationToken）
	 *
	 * @param authentication
	 * @return
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(UnionidAuthenticationToken.class);
	}
}
