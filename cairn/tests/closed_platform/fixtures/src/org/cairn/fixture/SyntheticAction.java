package org.cairn.fixture;

public final class SyntheticAction {
    private final PlatformSql sql;
    private final AuthorizationGuard authorization;
    private final TenantGuard tenants;

    public SyntheticAction(
            PlatformSql sql,
            AuthorizationGuard authorization,
            TenantGuard tenants) {
        this.sql = sql;
        this.authorization = authorization;
        this.tenants = tenants;
    }

    public String execute(PlatformRequest request) {
        if (!authorization.permits(request.userId(), "fixture:lookup")) {
            return "denied";
        }
        String targetTenant = request.parameter("tenant");
        if (!tenants.permits(request.tenantId(), targetTenant)) {
            return "denied";
        }
        return sql.queryForText(
                "select display_name from fixture_record where record_id = "
                        + request.parameter("id"));
    }
}
