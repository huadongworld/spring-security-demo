package com.meicloud.security.mall.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 买家
 *
 * @author HuaDong
 * @since 2021/5/9 18:18
 */
@RestController
@RequestMapping("/buyer")
public class BuyerController {

    /**
     * 买家下订单
     *
     * @return
     */
    @GetMapping("/order:create")
    public String receiveOrder() {
        return "买家下单啦！";
    }

    /**
     * 买家订单支付
     *
     * @return
     */
    @GetMapping("/order:pay")
    public String deliverOrder() {
        return "买家付款了！";
    }
}