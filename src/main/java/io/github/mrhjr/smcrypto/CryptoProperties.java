package io.github.mrhjr.smcrypto;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("sm-crypto")
public class CryptoProperties {
    private boolean enabled;
    private String activeKid;
    private Map<String, String> privateKeys = new LinkedHashMap<>();
    private List<String> paths = new ArrayList<>();
    private Duration clockSkew = Duration.ofMinutes(2);
    private int maxBodyBytes = 1024 * 1024;
    private int replayCapacity = 10_000;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getActiveKid() { return activeKid; }
    public void setActiveKid(String activeKid) { this.activeKid = activeKid; }
    public Map<String, String> getPrivateKeys() { return privateKeys; }
    public void setPrivateKeys(Map<String, String> privateKeys) { this.privateKeys = privateKeys; }
    public List<String> getPaths() { return paths; }
    public void setPaths(List<String> paths) { this.paths = paths; }
    public Duration getClockSkew() { return clockSkew; }
    public void setClockSkew(Duration clockSkew) { this.clockSkew = clockSkew; }
    public int getMaxBodyBytes() { return maxBodyBytes; }
    public void setMaxBodyBytes(int maxBodyBytes) { this.maxBodyBytes = maxBodyBytes; }
    public int getReplayCapacity() { return replayCapacity; }
    public void setReplayCapacity(int replayCapacity) { this.replayCapacity = replayCapacity; }
}
