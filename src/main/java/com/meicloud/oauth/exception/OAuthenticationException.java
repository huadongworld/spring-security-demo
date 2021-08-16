package com.meicloud.oauth.exception;

import lombok.Data;
import org.springframework.security.core.AuthenticationException;

/**
 * OAuth系统认证异常
 * @author
 */
@Data
public class OAuthenticationException extends AuthenticationException {

    /**
     * 6 = 三方接口授权/ 10 = 三方用户认证 后3位为错误码
     * 第4位代表验证程度 0->9 递增, 0=提醒(INFO) 5=警告(WARN) 9=致命错误(ERROR), 后两位为具体的错误码
     */
    private static final int BASE_CODE = 610000;

    public static OAuthenticationException CLIENT_QUERY_FAIL =
            new OAuthenticationException(BASE_CODE + 101, "CLIENT_QUERY_FAIL", "授权客户端信息查询失败！");

    /**
     * 响应码,成功200
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

    public OAuthenticationException(Integer code, String engDesc, String chnDesc) {
        super(engDesc);
        this.code = code;
        this.engDesc = engDesc;
        this.chnDesc = chnDesc;
    }

    public OAuthenticationException(String msg) {
        super(msg);
        this.engDesc = msg;
    }
}
