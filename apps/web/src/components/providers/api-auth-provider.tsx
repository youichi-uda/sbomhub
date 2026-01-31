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

  // Memoized token getter that ensures fresh token with organization context
  const getOrgScopedToken = useCallback(async () => {
    try {
      // SECURITY FIX: Always get a fresh token to ensure org claims are current
      // When user switches organizations via OrganizationSwitcher, Clerk updates
      // the session. Using skipCache ensures we get the latest token with
      // the current ActiveOrganizationID claim.
      return await getToken({ skipCache: true });
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
