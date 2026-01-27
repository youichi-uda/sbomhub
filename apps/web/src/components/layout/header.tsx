"use client";

import { usePathname, useRouter } from "next/navigation";
import { OrganizationSwitcher } from "@clerk/nextjs";
import { Button } from "@/components/ui/button";
import { Globe, LogOut } from "lucide-react";
import { isAuthEnabled, useAuth } from "@/lib/auth";

export function Header() {
  const pathname = usePathname();
  const router = useRouter();
  const { isSignedIn, signOut } = useAuth();
  const authEnabled = isAuthEnabled();

  const toggleLocale = () => {
    const currentLocale = pathname.startsWith("/en") ? "en" : "ja";
    const newLocale = currentLocale === "ja" ? "en" : "ja";
    const newPath = pathname.replace(`/${currentLocale}`, `/${newLocale}`);
    router.push(newPath || `/${newLocale}`);
  };

  const handleSignOut = async () => {
    if (!authEnabled) return;
    await signOut({ redirectUrl: "/" });
  };

  return (
    <header className="h-14 border-b bg-white flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <span className="text-sm text-muted-foreground">
          SBOM Management Dashboard
        </span>
        {authEnabled && isSignedIn && (
          <OrganizationSwitcher
            hidePersonal
            afterSelectOrganizationUrl={pathname}
            afterCreateOrganizationUrl={pathname}
            appearance={{
              elements: {
                rootBox: "flex items-center",
                organizationSwitcherTrigger: "px-2 py-1 rounded border text-sm",
              },
            }}
          />
        )}
      </div>
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={toggleLocale}>
          <Globe className="h-4 w-4 mr-1" />
          {pathname.startsWith("/en") ? "EN" : "JA"}
        </Button>
        {authEnabled && isSignedIn ? (
          <Button variant="ghost" size="sm" onClick={handleSignOut}>
            <LogOut className="h-4 w-4 mr-1" />
            {pathname.startsWith("/en") ? "Logout" : "ログアウト"}
          </Button>
        ) : null}
      </div>
    </header>
  );
}
