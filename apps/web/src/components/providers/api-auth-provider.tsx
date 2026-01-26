"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, ReactNode } from "react";
import { setAuthTokenGetter } from "@/lib/api";

interface ApiAuthProviderProps {
  children: ReactNode;
}

export function ApiAuthProvider({ children }: ApiAuthProviderProps) {
  const { getToken, isLoaded } = useAuth();

  useEffect(() => {
    if (isLoaded) {
      setAuthTokenGetter(async () => {
        try {
          return await getToken();
        } catch {
          return null;
        }
      });
    }
  }, [getToken, isLoaded]);

  return <>{children}</>;
}
