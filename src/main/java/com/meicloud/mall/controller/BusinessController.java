package com.meicloud.mall.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author HuaDong
 * @date 2021/5/9 23:19
 */
@RestController
@RequestMapping("/business")
public class BusinessController {

    /**
     * 店铺列表
     *
     * @return
     */
    @GetMapping("/stores")
    public String stores() {
        return "这是店铺列表！";
    }

    /**
     * 卖家列表
     *
     * @return
     */
    @GetMapping("/sellers")
    public String sellers() {
        return "这是卖家列表！";
    }

    /**
     * 买家列表
     *
     * @return
     */
    @GetMapping("/buyers")
    public String deliverOrder() {
        return "这是买家列表！";
    }
}
