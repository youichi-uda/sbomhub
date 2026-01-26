"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { jaJP, enUS } from "@clerk/localizations";
import { useParams } from "next/navigation";
import { ReactNode } from "react";

interface AuthProviderProps {
  children: ReactNode;
}

// Check if Clerk is configured
const isClerkEnabled = () => {
  return !!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
};

export function AuthProvider({ children }: AuthProviderProps) {
  const params = useParams();
  const locale = params?.locale as string;

  // Self-hosted mode: no auth provider needed
  if (!isClerkEnabled()) {
    return <>{children}</>;
  }

  // SaaS mode: wrap with ClerkProvider
  const localization = locale === "ja" ? jaJP : enUS;

  return (
    <ClerkProvider
      localization={localization}
      afterSignInUrl={`/${locale}/dashboard`}
      afterSignUpUrl={`/${locale}/dashboard`}
      signInUrl={`/${locale}/sign-in`}
      signUpUrl={`/${locale}/sign-up`}
    >
      {children}
    </ClerkProvider>
  );
}
