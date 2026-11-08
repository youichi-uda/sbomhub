"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, ReactNode, useCallback } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { setAuthTokenGetter, setOrgIdGetter } from "@/lib/api";
import { makeQueryClient } from "@/lib/query/client";
import { orgScopeKey } from "@/lib/query/org-scope";

interface ApiAuthProviderProps {
  children: ReactNode;
}

export function ApiAuthProvider({ children }: ApiAuthProviderProps) {
  const { getToken, isLoaded, orgId } = useAuth();
  // The org the API client's token / org getters are currently wired to;
  // undefined until Clerk has loaded and the getters are set.
  const [wiredOrg, setWiredOrg] = useState<string | null | undefined>(undefined);

  // Memoized token getter using custom JWT template with org claims
  const getOrgScopedToken = useCallback(async () => {
    try {
      // Use custom JWT template that includes org_id, org_role, org_slug
      const token = await getToken({ template: "sbomhub" });
      if (!token) {
        console.warn("[Auth] No token returned from Clerk for sbomhub template");
      }
      return token;
    } catch (error) {
      console.error("[Auth] Failed to get token from Clerk:", error);
      return null;
    }
  }, [getToken]);

  useEffect(() => {
    if (isLoaded) {
      setAuthTokenGetter(getOrgScopedToken);
      // Keep org ID getter for backwards compatibility (read-only info)
      setOrgIdGetter(() => orgId || null);
      // M12-5 #86: mirrors Clerk's `isLoaded` / `orgId` (external auth
      // state) into a local "wired" marker so children only mount after the
      // token getter is wired — for the org it is wired to. This is exactly
      // the "subscribe to an external system, update local state on signal"
      // pattern that react-hooks/set-state-in-effect explicitly allows;
      // there is no pre-render derivable substitute because `isLoaded`
      // flips asynchronously after Clerk's session bootstrap and the getters
      // are module-level state of the API client.
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Clerk isLoaded/orgId is external state; readiness must be reflected to children.
      setWiredOrg(orgId || null);
    }
  }, [getOrgScopedToken, isLoaded, orgId]);

  // Don't render children until the auth token getter is set up for the
  // CURRENT organisation (see lib/query/org-scope.ts).
  const scopeKey = isLoaded ? orgScopeKey(wiredOrg, orgId || null) : null;
  if (scopeKey === null) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return <OrgScopedQueryClient key={scopeKey}>{children}</OrgScopedQueryClient>;
}

// One QueryClient per organisation: re-created (and the subtree re-mounted)
// whenever the org-scope key changes. Same defaults as the app-wide client.
function OrgScopedQueryClient({ children }: { children: ReactNode }) {
  const [client] = useState(makeQueryClient);
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
