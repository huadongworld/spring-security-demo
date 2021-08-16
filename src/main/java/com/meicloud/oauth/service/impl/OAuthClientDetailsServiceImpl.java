package com.meicloud.oauth.service.impl;

import com.meicloud.oauth.exception.OAuthenticationException;
import com.meicloud.oauth.service.OAuthClientDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Array;
import java.util.*;

/**
 * OAuth 授权客户端信息服务类
 *
 * @author HuaDong
 * @since 2021/6/30 10:27
 */
@Service
@Slf4j
public class OAuthClientDetailsServiceImpl implements OAuthClientDetailsService, ClientDetailsService, ClientRegistrationService {

    @Override
    public Boolean hasPermission(HttpServletRequest request, Authentication authentication) {

        String clientId = (String) authentication.getPrincipal();

        // TODO 根据 clientId 查询该客户端所拥有的接口权限
        Set<String> urls = new HashSet<>();
        urls.add("GET /hello");

        if (urls.size() > 0) {
            return urls.stream().anyMatch(
                    url -> url.equalsIgnoreCase(request.getMethod() + " " + request.getServletPath()));
        }

        return false;
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {

        // TODO 根据 clientId 查询数据库数据，组装出 ClientDetails 返回（注意这里的常量值都应该是数据库查询出来的）
        if ("4099c23e45f64c158065e1b062492357".equalsIgnoreCase(clientId)) {

            BaseClientDetails details = new BaseClientDetails("4099c23e45f64c158065e1b062492357",
                    "security_oauth_demo_resource_id", "read,write",
                    "client_credentials,refresh_token,authorization_code", null,
                    null);
            details.setClientSecret("f5b351eb6df8458382d0303aae8a72d7275a2296ff45488c9f135ca120edebd1");

            return details;
        } else {
            log.error("查询授权客户端异常：e={}", "客户端不存在");
            throw OAuthenticationException.CLIENT_QUERY_FAIL;
        }

    }

    @Override
    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        // ignore...
    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        // ignore...
    }

    @Override
    public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        // ignore...
    }

    @Override
    public void removeClientDetails(String clientId) throws NoSuchClientException {
        // ignore...
    }

    @Override
    public List<ClientDetails> listClientDetails() {
        // ignore...
        return new ArrayList<>();
    }
}
