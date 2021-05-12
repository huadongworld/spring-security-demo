package com.meicloud.security.authorize;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author HuaDong
 * @since 2021/5/11 21:31
 */
@Component
public class ImplAuthorizeConfigManager implements AuthorizeConfigManager {

    private List<AuthorizeConfigProvider> authorizeConfigProviders;

    @Override
    public boolean config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {

        return false;
    }
}
