"use client";

import { useEffect, useState, ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Building2 } from "lucide-react";
import { OrganizationSwitcher } from "@clerk/nextjs";

interface SubscriptionGuardProps {
  children: ReactNode;
  locale: string;
}

// Pages that don't require subscription check
const EXEMPT_PATHS = [
  "/billing",
  "/sign-in",
  "/sign-up",
];

export function SubscriptionGuard({ children, locale }: SubscriptionGuardProps) {
  const [loading, setLoading] = useState(true);
  const [checked, setChecked] = useState(false);
  const [needsOrg, setNeedsOrg] = useState(false);
  const pathname = usePathname();
  const router = useRouter();
  const { orgId, isLoaded } = useAuth();

  useEffect(() => {
    if (!isLoaded) return;

    // Skip check for exempt paths
    const isExempt = EXEMPT_PATHS.some((path) => pathname.includes(path));
    if (isExempt) {
      setLoading(false);
      setChecked(true);
      return;
    }

    // Check if user has an organization selected
    if (!orgId) {
      setNeedsOrg(true);
      setLoading(false);
      return;
    }

    checkSubscription();
  }, [pathname, orgId, isLoaded]);

  const checkSubscription = async () => {
    try {
      const subscription = await api.billing.getSubscription();

      // Self-hosted mode - no subscription required
      if (subscription.is_self_hosted) {
        setLoading(false);
        setChecked(true);
        return;
      }

      // Billing not enabled - skip check
      if (!subscription.billing_enabled) {
        setLoading(false);
        setChecked(true);
        return;
      }

      // Has subscription or on free plan with usage within limits - allow access
      if (subscription.has_subscription || subscription.plan !== "free") {
        setLoading(false);
        setChecked(true);
        return;
      }

      // Free plan user - redirect to billing on first visit
      // Check if this is a new user (no projects yet)
      const usage = await api.billing.getUsage();

      // If user has no projects, they're likely new - redirect to billing
      if (usage.projects.current === 0) {
        router.replace(`/${locale}/billing`);
        return;
      }

      // Existing free user with projects - allow access
      setLoading(false);
      setChecked(true);
    } catch (error) {
      // On error, allow access (don't block users)
      console.error("Subscription check failed:", error);
      setLoading(false);
      setChecked(true);
    }
  };

  // Show organization selection if user has no org
  if (needsOrg) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <Card className="w-full max-w-md mx-4">
          <CardHeader className="text-center">
            <Building2 className="h-12 w-12 mx-auto text-primary mb-4" />
            <CardTitle>組織を選択してください</CardTitle>
            <CardDescription>
              SBOMHub を使用するには、組織を作成または選択する必要があります。
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4">
            <OrganizationSwitcher
              hidePersonal
              afterCreateOrganizationUrl={pathname}
              afterSelectOrganizationUrl={pathname}
              appearance={{
                elements: {
                  rootBox: "w-full",
                  organizationSwitcherTrigger: "w-full justify-center px-4 py-3 border rounded-lg",
                },
              }}
            />
            <p className="text-sm text-muted-foreground text-center">
              組織を作成するか、招待された組織を選択してください。
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (loading && !checked) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <>{children}</>;
}
