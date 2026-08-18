package dev.mahadi.toolgate.gateway;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "toolgate.approvals")
@Component
public class ApprovalProperties {

    /**
     * Where to keep outstanding approval requests. Empty means memory only, and a restart
     * empties the operator's queue.
     */
    private String file = "";

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }
}
