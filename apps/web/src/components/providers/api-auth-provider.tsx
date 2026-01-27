"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, ReactNode } from "react";
import { setAuthTokenGetter } from "@/lib/api";

interface ApiAuthProviderProps {
  children: ReactNode;
}

export function ApiAuthProvider({ children }: ApiAuthProviderProps) {
  const { getToken, isLoaded } = useAuth();
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    if (isLoaded) {
      setAuthTokenGetter(async () => {
        try {
          return await getToken();
        } catch {
          return null;
        }
      });
      setIsReady(true);
    }
  }, [getToken, isLoaded]);

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
