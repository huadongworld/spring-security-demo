package com.meicloud.sentinel.entity;

import java.util.Set;

/**
 * @author Eric Zhao
 * @since 1.4.1
 */
public class ClusterGroupEntity {

    private String serverId;
    private String ip;
    private Integer port;

    private Set<String> clientSet;

    public String getServerId() {
        return serverId;
    }

    public ClusterGroupEntity setServerId(String serverId) {
        this.serverId = serverId;
        return this;
    }

    public String getIp() {
        return ip;
    }

    public ClusterGroupEntity setIp(String ip) {
        this.ip = ip;
        return this;
    }

    public Integer getPort() {
        return port;
    }

    public ClusterGroupEntity setPort(Integer port) {
        this.port = port;
        return this;
    }

    public Set<String> getClientSet() {
        return clientSet;
    }

    public ClusterGroupEntity setClientSet(Set<String> clientSet) {
        this.clientSet = clientSet;
        return this;
    }

    @Override
    public String toString() {
        return "ClusterGroupEntity{" +
                "machineId='" + serverId + '\'' +
                ", ip='" + ip + '\'' +
                ", port=" + port +
                ", clientSet=" + clientSet +
                '}';
    }
}
