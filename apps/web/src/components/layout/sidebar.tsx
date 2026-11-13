"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { FolderOpen, LayoutDashboard, Search, ClipboardList, TrendingUp, FileText, CreditCard, Key, Settings, Plug, Sparkles, Menu } from "lucide-react";

// The fixed 256px sidebar left 64px for the page at a 320px viewport, so
// every dashboard page scrolled sideways on a phone. Below `md` the sidebar
// is hidden and the same links open from the header's menu button
// (MobileNav) in a modal panel; from `md` up nothing changes.
export function Sidebar() {
  return (
    <aside className="hidden md:block w-64 shrink-0 bg-gray-900 text-white min-h-screen p-4">
      <div className="mb-8">
        <h1 className="text-2xl font-bold">SBOMHub</h1>
      </div>
      <SidebarNav />
    </aside>
  );
}

export function MobileNav() {
  const t = useTranslations("Navigation");
  const [open, setOpen] = useState(false);
  // Any navigation (a link, Back / Forward) closes it: the state is reset
  // while rendering the new pathname (React's "adjust state on prop change"
  // pattern), so returning to the page later does not reopen it (Codex R1
  // Medium-1). A link to the page already shown does not change the
  // pathname, so the links also close it themselves (onNavigate).
  const pathname = usePathname();
  const [shownOn, setShownOn] = useState(pathname);
  if (shownOn !== pathname) {
    setShownOn(pathname);
    setOpen(false);
  }
  // Growing past md hides this wrapper (md:hidden) but would leave the
  // modal's focus trap and Escape listener live: close it instead.
  useEffect(() => {
    if (!open) return;
    const wide = window.matchMedia("(min-width: 768px)");
    const close = () => {
      if (wide.matches) setOpen(false);
    };
    close();
    wide.addEventListener("change", close);
    return () => wide.removeEventListener("change", close);
  }, [open]);

  return (
    <div className="md:hidden">
      <button
        type="button"
        className="-ml-2 inline-flex h-9 w-9 items-center justify-center rounded-md text-gray-700 hover:bg-gray-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label={t("openMenu")}
        aria-haspopup="dialog"
        aria-expanded={open}
        data-testid="mobile-nav-toggle"
        onClick={() => setOpen(true)}
      >
        <Menu className="h-5 w-5" aria-hidden="true" />
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          aria-label={t("mainMenu")}
          onClose={() => setOpen(false)}
          closeLabel={t("closeMenu")}
          className="w-[min(18rem,calc(100vw-2rem))] max-h-[calc(100dvh-2rem)] overflow-y-auto bg-gray-900 p-4 text-white"
        >
          <p className="mb-6 text-2xl font-bold">SBOMHub</p>
          <SidebarNav onNavigate={() => setOpen(false)} />
        </DialogContent>
      </Dialog>
    </div>
  );
}

function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const t = useTranslations("Navigation");
  const tSettings = useTranslations("Settings.APIKeys");
  const tLLM = useTranslations("Settings.LLM");
  const pathname = usePathname();

  const links = [
    { href: "/dashboard", icon: LayoutDashboard, label: t("dashboard") },
    { href: "/analytics", icon: TrendingUp, label: t("analytics") },
    { href: "/reports", icon: FileText, label: t("reports") },
    { href: "/search", icon: Search, label: t("search") },
    { href: "/projects", icon: FolderOpen, label: t("projects") },
    { href: "/audit", icon: ClipboardList, label: t("audit") },
    { href: "/billing", icon: CreditCard, label: t("billing") },
  ];

  const settingsLinks = [
    { href: "/settings/apikeys", icon: Key, label: tSettings("title") },
    { href: "/settings/integrations", icon: Plug, label: t("integrations") },
    { href: "/settings/llm", icon: Sparkles, label: tLLM("navTitle") },
  ];

  return (
    <>
      <nav className="space-y-2">
        {links.map((link) => {
          const Icon = link.icon;
          const isActive = pathname.endsWith(link.href) || (link.href !== "/" && pathname.includes(link.href));
          return (
            <Link
              key={link.href}
              href={link.href}
              onClick={onNavigate}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md transition-colors",
                isActive ? "bg-gray-700 text-white" : "text-gray-300 hover:bg-gray-800"
              )}
            >
              <Icon className="h-5 w-5" />
              {link.label}
            </Link>
          );
        })}
      </nav>

      {/* Settings Section */}
      <div className="mt-8 pt-4 border-t border-gray-700">
        <div className="flex items-center gap-2 px-3 mb-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
          <Settings className="h-4 w-4" />
          {t("settings")}
        </div>
        <nav className="space-y-1">
          {settingsLinks.map((link) => {
            const Icon = link.icon;
            const isActive = pathname.includes(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                onClick={onNavigate}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md transition-colors",
                  isActive ? "bg-gray-700 text-white" : "text-gray-300 hover:bg-gray-800"
                )}
              >
                <Icon className="h-5 w-5" />
                {link.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </>
  );
}
