"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { jaJP, enUS } from "@clerk/localizations";
import { useParams } from "next/navigation";
import { ReactNode } from "react";

const CLERK_PUBLISHABLE_KEY = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;

interface AuthLayoutProps {
  children: ReactNode;
}

export default function AuthLayout({ children }: AuthLayoutProps) {
  const params = useParams();
  const locale = (params?.locale as string) || "ja";
  const localization = locale === "ja" ? jaJP : enUS;

  // Self-hosted mode - auth pages shouldn't be accessible
  if (!CLERK_PUBLISHABLE_KEY) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">Self-Hosted Mode</h1>
          <p className="text-gray-600 mb-4">Authentication is disabled in self-hosted mode.</p>
          <a href={`/${locale}`} className="text-blue-600 hover:underline">
            Go to Dashboard
          </a>
        </div>
      </div>
    );
  }

  // SaaS mode - wrap with ClerkProvider
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
