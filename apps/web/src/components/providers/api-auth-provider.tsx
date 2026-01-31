"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, ReactNode, useCallback, useRef } from "react";
import { setAuthTokenGetter, setOrgIdGetter } from "@/lib/api";

interface ApiAuthProviderProps {
  children: ReactNode;
}

export function ApiAuthProvider({ children }: ApiAuthProviderProps) {
  const { getToken, isLoaded, orgId } = useAuth();
  const [isReady, setIsReady] = useState(false);

  // Use ref to track the current orgId for the token getter
  const orgIdRef = useRef(orgId);
  orgIdRef.current = orgId;

  // Memoized token getter that includes organization context
  const getOrgScopedToken = useCallback(async () => {
    try {
      const currentOrgId = orgIdRef.current;
      if (currentOrgId) {
        // SECURITY FIX: Get organization-scoped token
        // This ensures the JWT includes the organization ID in its claims
        // The backend will verify the org ID from JWT, not from headers
        return await getToken({ organizationId: currentOrgId });
      }
      // Fall back to regular token if no org selected
      return await getToken();
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
