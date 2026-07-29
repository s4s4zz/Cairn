package org.cairn.fixture;

public final class AuthorizationGuard {
    public boolean permits(String userId, String permission) {
        return userId != null && permission.equals("fixture:lookup");
    }
}
