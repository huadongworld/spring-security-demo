package com.meicloud.sentinel.controller;

import com.alibaba.csp.sentinel.AsyncEntry;
import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.SphO;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.annotation.SentinelResource;
import com.alibaba.csp.sentinel.context.ContextUtil;
import com.alibaba.csp.sentinel.slots.block.BlockException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 限流使用方式
 *
 * @author HuaDong
 * @since 2021/5/9 18:18
 */
@Slf4j
@RestController
@RequestMapping("/sentinel")
public class SentinelWaysController {

    /**
     * 方式一：主流框架的默认适配，例如 Web Servlet、Dubbo、Spring Cloud、gRPC、Spring WebFlux、Reactor 等都做了适配
     * <p>
     * ======================================
     * <p>
     * 方式二：抛出异常的方式定义资源
     *
     * @return
     */
    @GetMapping("/way2")
    public void way2(HttpServletRequest request, HttpServletResponse response) {

        Entry entry = null;
        // 1.5.0 版本开始可以利用 try-with-resources 特性（使用有限制）
        // 资源名可使用任意有业务语义的字符串，比如方法名、接口名或其它可唯一标识的字符串。
        try {

            ContextUtil.enter("sentinel_myself_content", "");

            entry = SphU.entry("way2");
            // 被保护的业务逻辑
            // do something here...

            log.info("way2 执行成功√√√");

        } catch (BlockException ex) {
            // 资源访问阻止，被限流或被降级
            // 在此处进行相应的处理操作

            log.error("way2 被限流了×××");

        } finally {
            // 务必保证 exit，务必保证每个 entry 与 exit 配对
            if (entry != null) {
                entry.exit();
            }

            ContextUtil.exit();
        }
    }

    /**
     * 方式三：返回布尔值方式定义资源
     *
     * @return
     */
    @GetMapping("/way3")
    public void way3(HttpServletRequest request, HttpServletResponse response) {
        // 资源名可使用任意有业务语义的字符串
        if (SphO.entry("way3")) {
            // 务必保证finally会被执行
            try {
                // 被保护的业务逻辑
                log.info("way3 执行成功√√√");
            } finally {
                SphO.exit();
            }
        } else {
            // 资源访问阻止，被限流或被降级
            // 进行相应的处理操作

            log.error("way3 被限流了×××");
        }
    }

    /**
     * 方式四：注解方式定义资源
     * <p>
     * 注解的方式需要引入以下依赖：
     *
     * <dependency>
     *   <groupId>com.alibaba.csp</groupId>
     *   <artifactId>sentinel-annotation-aspectj</artifactId>
     *   <version>1.8.1</version>
     *   </dependency>
     * <p>
     * 同时要创建 SentinelResourceAspect对象（AopConfiguration配置）
     * <p>
     * 或者你是通过 Spring Cloud Alibaba 接入的 Sentinel，则无需额外进行配置即可使用 @SentinelResource 注解。
     *
     * @return
     */
    @GetMapping("/way4")
    @SentinelResource(value = "way4", blockHandler = "way4BlockHandler", defaultFallback = "defaultFallback")
    public void way4(HttpServletRequest request, HttpServletResponse response) {
        log.info("way4 执行成功√√√");
    }

    /**
     * blockHandler 函数访问范围需要是 public，返回类型需要与原方法相匹配，
     * 参数类型需要和原方法相匹配并且最后加一个额外的参数，类型为 BlockException。
     * blockHandler 函数默认需要和原方法在同一个类中。
     *
     * 若希望使用其他类的函数，则可以指定 blockHandlerClass 为对应的类的 Class 对象，注意对应的函数必需为 static 函数，否则无法解析。
     *
     * @param request
     * @param response
     * @param blockException
     */
    public void way4BlockHandler(HttpServletRequest request, HttpServletResponse response, BlockException blockException) {
        log.error("way4 被限流了×××");
    }

    public void defaultFallback() {
        log.error("way4 接口报错啦 ！");
    }

    /**
     * 方式五：异步调用支持
     *
     * @return
     */
    @GetMapping("/way5")
    public void way5(HttpServletRequest request, HttpServletResponse response) {
        try {
            AsyncEntry entry = SphU.asyncEntry("way5");

            log.info("way5 执行成功√√√");

            // 异步调用.
            //            doAsync(userId, result -> {
            //                try {
            //                    // 在此处处理异步调用的结果.
            //                } finally {
            //                    // 在回调结束后 exit.
            //                    entry.exit();
            //                }
            //            });
        } catch (BlockException ex) {
            // Request blocked.
            // Handle the exception (e.g. retry or fallback).

            log.error("way5 被限流了×××");
        }

    }
}