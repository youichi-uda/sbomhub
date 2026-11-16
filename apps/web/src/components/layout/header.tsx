"use client";

import { usePathname, useRouter } from "next/navigation";
import { OrganizationSwitcher } from "@clerk/nextjs";
import { Button } from "@/components/ui/button";
import { Globe, LogOut } from "lucide-react";
import { isAuthEnabled, useAuth } from "@/lib/auth";
import { MobileNav } from "@/components/layout/sidebar";

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
    <header className="h-14 border-b bg-white flex items-center justify-between gap-2 px-4 md:px-6">
      {/* Login mode at 320px: the organization switcher and Logout did not
          fit next to the menu and locale buttons, and nothing could shrink,
          so the page scrolled 67px sideways. The switcher now takes the space
          that is left and truncates the organization name; Logout is
          icon-only below sm (its name stays for screen readers). */}
      <div className="flex min-w-0 flex-1 items-center gap-2 sm:gap-4">
        <MobileNav />
        <span className="hidden sm:inline text-sm text-muted-foreground">
          SBOM Management Dashboard
        </span>
        {authEnabled && isSignedIn && (
          <div className="min-w-0">
            <OrganizationSwitcher
              hidePersonal
              afterSelectOrganizationUrl={pathname}
              afterCreateOrganizationUrl={pathname}
              appearance={{
                elements: {
                  rootBox: "flex min-w-0 max-w-full items-center",
                  organizationSwitcherTrigger: "min-w-0 max-w-full px-2 py-1 rounded border text-sm",
                  organizationPreview: "min-w-0",
                  organizationPreviewTextContainer: "min-w-0",
                  organizationPreviewMainIdentifier: "truncate",
                },
              }}
            />
          </div>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-1 sm:gap-2">
        <Button variant="ghost" size="sm" onClick={toggleLocale}>
          <Globe className="h-4 w-4 mr-1" />
          {pathname.startsWith("/en") ? "EN" : "JA"}
        </Button>
        {authEnabled && isSignedIn ? (
          <Button variant="ghost" size="sm" onClick={handleSignOut}>
            <LogOut className="h-4 w-4 sm:mr-1" />
            <span className="sr-only sm:not-sr-only">{pathname.startsWith("/en") ? "Logout" : "ログアウト"}</span>
          </Button>
        ) : null}
      </div>
    </header>
  );
}
