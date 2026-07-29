package org.cairn.fixture;

public final class TenantGuard {
    public boolean permits(String tenantId, String requestedTenantId) {
        return tenantId != null && tenantId.equals(requestedTenantId);
    }
}
