"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Globe } from "lucide-react";

export function Header() {
  const pathname = usePathname();
  const router = useRouter();

  const toggleLocale = () => {
    const currentLocale = pathname.startsWith("/en") ? "en" : "ja";
    const newLocale = currentLocale === "ja" ? "en" : "ja";
    const newPath = pathname.replace(`/${currentLocale}`, `/${newLocale}`);
    router.push(newPath || `/${newLocale}`);
  };

  return (
    <header className="h-14 border-b bg-white flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <span className="text-sm text-muted-foreground">
          SBOM Management Dashboard
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={toggleLocale}>
          <Globe className="h-4 w-4 mr-1" />
          {pathname.startsWith("/en") ? "EN" : "JA"}
        </Button>
      </div>
    </header>
  );
}
