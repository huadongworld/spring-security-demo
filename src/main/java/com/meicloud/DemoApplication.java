package com.meicloud;

import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.slots.block.BlockException;
import com.alibaba.csp.sentinel.slots.block.RuleConstant;
import com.alibaba.csp.sentinel.slots.block.flow.FlowRule;
import com.alibaba.csp.sentinel.slots.block.flow.FlowRuleManager;
import com.alibaba.csp.sentinel.slots.clusterbuilder.ClusterBuilderSlot;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * @author HuaDong
 * @date 2021/4/24 10:33
 */
@SpringBootApplication
@RestController
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);

//        testQPSCount();

    }

    private static void testQPSCount() {
        // 下面几行代码设置了 QPS 阈值是 100
        FlowRule rule = new FlowRule("test");
        rule.setGrade(RuleConstant.FLOW_GRADE_QPS);
        rule.setCount(100);
        rule.setControlBehavior(RuleConstant.CONTROL_BEHAVIOR_DEFAULT);
        List<FlowRule> list = new ArrayList<>();
        list.add(rule);
        FlowRuleManager.loadRules(list);

        // 先通过一个请求，让 clusterNode 先建立起来
        try (Entry entry = SphU.entry("test")) {
        } catch (BlockException e) {
        }

        // 起一个线程一直打印 qps 数据
        new Thread(() -> {
            while (true) {
                System.out.println(ClusterBuilderSlot.getClusterNode("test").passQps());
            }
        }).start();

        while (true) {
            try (Entry entry = SphU.entry("test")) {
                Thread.sleep(5);
            } catch (BlockException e) {
                // ignore
            } catch (InterruptedException e) {
                // ignore
            }
        }
    }

    /**
     * 用户登录才可访问
     *
     * @return
     */
    @GetMapping("/hello")
    public String hello() {
        return "Hello Spring Security!";
    }

    /**
     * 用户登录才可访问
     *
     * @return
     */
    @GetMapping("/bye")
    public String bye() {
        return "Bye Spring Security!";
    }

    /**
     * 广告接口，匿名用户可以访问
     *
     * @return
     */
    @GetMapping("/ad")
    public String no() {
        return "妈妈再也不用担心我的学习！";
    }
}
