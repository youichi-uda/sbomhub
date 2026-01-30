"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";
import { FolderOpen, LayoutDashboard, Search, ClipboardList, TrendingUp, FileText, CreditCard, Key, Settings, Plug } from "lucide-react";

export function Sidebar() {
  const t = useTranslations("Navigation");
  const tSettings = useTranslations("Settings.APIKeys");
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
  ];

  return (
    <aside className="w-64 bg-gray-900 text-white min-h-screen p-4">
      <div className="mb-8">
        <h1 className="text-2xl font-bold">SBOMHub</h1>
      </div>
      <nav className="space-y-2">
        {links.map((link) => {
          const Icon = link.icon;
          const isActive = pathname.endsWith(link.href) || (link.href !== "/" && pathname.includes(link.href));
          return (
            <Link
              key={link.href}
              href={link.href}
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
    </aside>
  );
}
