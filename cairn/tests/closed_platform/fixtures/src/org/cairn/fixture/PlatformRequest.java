package org.cairn.fixture;

import java.util.Map;

public final class PlatformRequest {
    private final Map<String, String> parameters;
    private final String userId;
    private final String tenantId;

    public PlatformRequest(Map<String, String> parameters, String userId, String tenantId) {
        this.parameters = Map.copyOf(parameters);
        this.userId = userId;
        this.tenantId = tenantId;
    }

    public String parameter(String name) {
        return parameters.get(name);
    }

    public String userId() {
        return userId;
    }

    public String tenantId() {
        return tenantId;
    }
}
