package com.meicloud.security.mall.service;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import com.meicloud.security.dto.JwtUserLoginDTO;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

/**
 * @author HuaDong
 * @date 2021/5/9 23:26
 */
@Component("rbacService")
public class RbacServiceImpl implements RbacService {

	private AntPathMatcher antPathMatcher = new AntPathMatcher();

	@Override
	public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
		Object principal = authentication.getPrincipal();

		boolean hasPermission = false;

		if (principal instanceof JwtUserLoginDTO) {
			// 如果角色是“ROLE_ADMIN”，就永远返回true
			if (StringUtils.equals(((JwtUserLoginDTO) principal).getRoleName(), "ROLE_ADMIN")) {
				hasPermission = true;
			} else {
				// 查询用户角色所拥有权限的所有URL，这里假设是从数据库或缓存（或者登录的时候可以直接将该角色拥有的权限保存到JWT）中查的
				List<String> urls = Arrays.asList("/business/stores", "/business/sellers");
				for (String url : urls) {
					if (antPathMatcher.match(url, request.getRequestURI())) {
						hasPermission = true;
						break;
					}
				}
			}
		}

		return hasPermission;
	}

}
