package com.meicloud.oauth.service;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * @author HuaDong
 * @since 2021/6/30 10:33
 */
public interface OAuthClientDetailsService {

    /**
     * 是否有权限访问
     *
     * @param request
     * @param authentication
     * @return
     */
    Boolean hasPermission(HttpServletRequest request, Authentication authentication);
}
