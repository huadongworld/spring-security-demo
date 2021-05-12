package com.meicloud.security.authorize;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

/**
 * 权限信息管理器
 *
 * @author HuaDong
 * @since 2021/5/11 21:23
 */
public interface AuthorizeConfigManager {

    /**
     * @param config
     * @return
     */
    boolean config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config);
}
