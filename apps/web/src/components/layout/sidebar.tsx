"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTranslations } from "next-intl";
import { cn } from "@/lib/utils";
import { FolderOpen, LayoutDashboard, Search, ClipboardList, TrendingUp, FileText, CreditCard } from "lucide-react";

export function Sidebar() {
  const t = useTranslations("Navigation");
  const pathname = usePathname();

  const links = [
    { href: "/dashboard", icon: LayoutDashboard, label: "ダッシュボード" },
    { href: "/analytics", icon: TrendingUp, label: "トレンド分析" },
    { href: "/reports", icon: FileText, label: "レポート" },
    { href: "/search", icon: Search, label: "横断検索" },
    { href: "/projects", icon: FolderOpen, label: t("projects") },
    { href: "/audit", icon: ClipboardList, label: "監査ログ" },
    { href: "/settings/billing", icon: CreditCard, label: "プラン・お支払い" },
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
    </aside>
  );
}
