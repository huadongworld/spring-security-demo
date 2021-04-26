package com.meicloud.security.request;

import lombok.Data;

import java.io.Serializable;

/**
 * 接收登录请求
 *
 * @author HuaDong
 * @since 2021/4/26 17:02
 */
@Data
public class UserLoginRequest implements Serializable {

    /**
     * 登录账号/手机号
     */
    private String mobile;

    /**
     * 登录密码
     */
    private String password;

    /**
     * 验证码
     */
    private String verifyCode;
}
