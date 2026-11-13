import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { AuthProvider } from "@/components/providers/auth-provider";
import { SubscriptionGuard } from "@/components/providers/subscription-guard";
import { ReactNode } from "react";
import { headers } from "next/headers";

interface DashboardLayoutProps {
  children: ReactNode;
  params: Promise<{ locale: string }>;
}

export default async function DashboardLayout({ children, params }: DashboardLayoutProps) {
  const { locale } = await params;
  // M71: the Clerk script tag is server-rendered and needs this request's
  // CSP nonce (set by src/proxy.ts).
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <AuthProvider locale={locale} nonce={nonce}>
      <SubscriptionGuard locale={locale}>
        <div className="flex min-h-screen">
          <Sidebar />
          {/* min-w-0: a flex item defaults to min-width:auto, so a wide table
              stretched the column (and the page) instead of scrolling in
              its own overflow-x-auto box. */}
          <div className="flex-1 min-w-0 flex flex-col">
            <Header />
            <main className="flex-1 min-w-0 bg-gray-50 p-4 md:p-6">{children}</main>
          </div>
        </div>
      </SubscriptionGuard>
    </AuthProvider>
  );
}
