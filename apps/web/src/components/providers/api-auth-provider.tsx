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
      return await getToken({ template: "sbomhub" });
    } catch {
      return null;
    }
  }, [getToken]);

  useEffect(() => {
    if (isLoaded) {
      setAuthTokenGetter(getOrgScopedToken);
      // Keep org ID getter for backwards compatibility (read-only info)
      setOrgIdGetter(() => orgId || null);
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
