"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { jaJP, enUS } from "@clerk/localizations";
import { useParams } from "next/navigation";
import { ReactNode } from "react";

interface AuthProviderProps {
  children: ReactNode;
}

// Check at build time - direct access for proper inlining
const CLERK_PUBLISHABLE_KEY = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;

export function AuthProvider({ children }: AuthProviderProps) {
  const params = useParams();
  const locale = (params?.locale as string) || "ja";

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
      {children}
    </ClerkProvider>
  );
}
