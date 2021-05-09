package com.meicloud.mall.service;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;

/**
 * @author HuaDong
 * @date 2021/5/9 23:26
 */
public interface RbacService {

	/**
	 * 是否有权限访问
	 *
	 * @param request
	 * @param authentication
	 * @return
	 */
	boolean hasPermission(HttpServletRequest request, Authentication authentication);
}
