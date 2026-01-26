"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { jaJP, enUS } from "@clerk/localizations";
import { ReactNode } from "react";
import { ApiAuthProvider } from "./api-auth-provider";

interface AuthProviderProps {
  children: ReactNode;
  locale: string;
}

// Check at build time - direct access for proper inlining
const CLERK_PUBLISHABLE_KEY = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;

export function AuthProvider({ children, locale }: AuthProviderProps) {
  // Self-hosted mode: no auth provider needed
  if (!CLERK_PUBLISHABLE_KEY) {
    return <>{children}</>;
  }

  // SaaS mode: wrap with ClerkProvider
  const localization = locale === "ja" ? jaJP : enUS;

  return (
    <ClerkProvider
      publishableKey={CLERK_PUBLISHABLE_KEY}
      localization={localization}
      afterSignInUrl={`/${locale}`}
      afterSignUpUrl={`/${locale}`}
      signInUrl={`/${locale}/sign-in`}
      signUpUrl={`/${locale}/sign-up`}
    >
      <ApiAuthProvider>{children}</ApiAuthProvider>
    </ClerkProvider>
  );
}
