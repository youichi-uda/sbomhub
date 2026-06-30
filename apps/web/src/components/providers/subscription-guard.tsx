"use client";

import { useEffect, useState, useCallback, ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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

  // M11 Phase D F170: checkSubscription captures `router` and `locale`,
  // so it must be in the effect deps to avoid stale-closure bugs as the
  // guard evolves. Hoist it via useCallback so the identity is stable
  // across re-renders and pin its own [router, locale] deps.
  const checkSubscription = useCallback(async () => {
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

      // Has a plan selected (including "free") - allow access
      if (subscription.plan && subscription.plan !== "") {
        setLoading(false);
        setChecked(true);
        return;
      }

      // No plan selected yet - redirect to billing to select a plan
      router.replace(`/${locale}/billing`);
    } catch (error) {
      // On error, allow access (don't block users)
      console.error("Subscription check failed:", error);
      setLoading(false);
      setChecked(true);
    }
  }, [router, locale]);

  useEffect(() => {
    if (!isLoaded) return;

    // Skip check for exempt paths
    const isExempt = EXEMPT_PATHS.some((path) => pathname.includes(path));
    if (isExempt) {
      // M12-5 #86: the exempt branch mirrors the pathname-driven (external
      // route state) decision into local `loading`/`checked` flags. The
      // value depends on the live pathname, so a useMemo-derived initial
      // state would not catch route changes after mount. This is the
      // "subscribe to external system" pattern set-state-in-effect allows.
      // eslint-disable-next-line react-hooks/set-state-in-effect -- pathname is external nav state; exempt branch must publish completion to consumers.
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
  }, [pathname, orgId, isLoaded, checkSubscription]);

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
              afterCreateOrganizationUrl={`/${locale}/billing`}
              afterSelectOrganizationUrl={`/${locale}/billing`}
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
