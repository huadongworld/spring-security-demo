package com.meicloud.security.exception;

import lombok.Data;
import org.springframework.security.core.AuthenticationException;

/**
 * 认证异常
 *
 * @author HuaDong
 * @since 2021/4/26 17:25
 */
@Data
public class LoginAuthenticationException extends AuthenticationException {

    public static LoginAuthenticationException VERIFY_CODE_INVALID =
            new LoginAuthenticationException(100001, "VERIFY_CODE_INVALID", "验证码无效！");

    public static LoginAuthenticationException USER_NAME_NOT_EXIST =
            new LoginAuthenticationException(100003, "USER_NAME_NOT_EXIST", "用户不存在！");

    public static LoginAuthenticationException PASSWORD_NOT_EXIST =
            new LoginAuthenticationException(100005, "PASSWORD_NOT_EXIST", "密码错误！");

    /**
     * 响应码，成功200
     */
    private Integer code;

    /**
     * 响应英文描述
     */
    private String engDesc;

    /**
     * 响应中文描述
     */
    private String chnDesc;

    /**
     * 响应描述明细
     */
    private String detail;

    public LoginAuthenticationException(Integer code, String engDesc, String chnDesc) {
        super(engDesc);
        this.code = code;
        this.engDesc = engDesc;
        this.chnDesc = chnDesc;
    }

    public LoginAuthenticationException(String msg) {
        super(msg);
        this.engDesc = msg;
    }

    public String toJSONString() {
        return "{    \"chnDesc\": \"" + chnDesc + "\",\n" +
                "    \"code\": " + code + ",\n" +
                "    \"engDesc\": \"" + engDesc + "\",\n" +
                "    \"message\": \"" + detail + "\"}";
    }
}
