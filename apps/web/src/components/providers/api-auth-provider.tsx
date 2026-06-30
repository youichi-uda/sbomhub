"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, ReactNode, useCallback } from "react";
import { setAuthTokenGetter, setOrgIdGetter } from "@/lib/api";

interface ApiAuthProviderProps {
  children: ReactNode;
}

export function ApiAuthProvider({ children }: ApiAuthProviderProps) {
  const { getToken, isLoaded, orgId } = useAuth();
  const [isReady, setIsReady] = useState(false);

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
      // M12-5 #86: setIsReady mirrors Clerk's `isLoaded` (external auth
      // state) into a local readiness flag so children only mount after
      // the token getter is wired. This is exactly the "subscribe to an
      // external system, update local state on signal" pattern that
      // react-hooks/set-state-in-effect explicitly allows; there is no
      // pre-render derivable substitute because `isLoaded` flips
      // asynchronously after Clerk's session bootstrap.
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Clerk isLoaded is external state; readiness must be reflected to children.
      setIsReady(true);
    }
  }, [getOrgScopedToken, isLoaded, orgId]);

  // Don't render children until auth token getter is set up
  if (!isReady) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return <>{children}</>;
}
