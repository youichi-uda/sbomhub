import { Sidebar } from "@/components/layout/sidebar";
import { Header } from "@/components/layout/header";
import { AuthProvider } from "@/components/providers/auth-provider";
import { ReactNode } from "react";

interface DashboardLayoutProps {
  children: ReactNode;
  params: Promise<{ locale: string }>;
}

export default async function DashboardLayout({ children, params }: DashboardLayoutProps) {
  const { locale } = await params;

  return (
    <AuthProvider locale={locale}>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex-1 flex flex-col">
          <Header />
          <main className="flex-1 bg-gray-50 p-6">{children}</main>
        </div>
      </div>
    </AuthProvider>
  );
}
