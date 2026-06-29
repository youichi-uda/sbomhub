// Note on rules-of-hooks (M11-5 #80):
// The mode switch below (`isAuthEnabled()`) is driven by
// `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, which Next.js inlines at BUILD time.
// For any given build artifact the branch is a compile-time constant, so the
// hook call order is stable across renders. The `react-hooks/rules-of-hooks`
// inline disables in this file mark the deliberate self-hosted-vs-SaaS fork
// and must NOT be removed without restructuring useAuth / useUser /
// useOrganization into separate hooks per mode.
import { useAuth as useClerkAuth, useUser as useClerkUser, useOrganization as useClerkOrg } from "@clerk/nextjs";

// Check if Clerk is configured (SaaS mode)
export const isAuthEnabled = () => {
  return !!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
};

// Check if billing is enabled
export const isBillingEnabled = () => {
  return isAuthEnabled(); // For now, billing requires auth
};

// Self-hosted mode: no restrictions
export const isSelfHosted = () => {
  return !isAuthEnabled();
};

// Hook that works in both modes
export function useAuth() {
  // In self-hosted mode, return a mock auth state
  if (!isAuthEnabled()) {
    return {
      isLoaded: true,
      isSignedIn: true,
      userId: "self-hosted",
      sessionId: "self-hosted",
      orgId: "self-hosted",
      orgRole: "admin",
      orgSlug: "default",
      signOut: () => Promise.resolve(),
      getToken: () => Promise.resolve(null),
    };
  }

  // In SaaS mode, use Clerk.
  // eslint-disable-next-line react-hooks/rules-of-hooks -- build-time branch via NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY; see header comment.
  const auth = useClerkAuth();
  return {
    isLoaded: auth.isLoaded,
    isSignedIn: auth.isSignedIn ?? false,
    userId: auth.userId,
    sessionId: auth.sessionId,
    orgId: auth.orgId,
    orgRole: auth.orgRole,
    orgSlug: auth.orgSlug,
    signOut: auth.signOut,
    getToken: auth.getToken,
  };
}

// Hook for user data
export function useUser() {
  if (!isAuthEnabled()) {
    return {
      isLoaded: true,
      isSignedIn: true,
      user: {
        id: "self-hosted",
        firstName: "Admin",
        lastName: "",
        fullName: "Administrator",
        primaryEmailAddress: { emailAddress: "admin@localhost" },
        imageUrl: null,
      },
    };
  }

  // eslint-disable-next-line react-hooks/rules-of-hooks -- build-time branch via NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY; see header comment.
  const { isLoaded, isSignedIn, user } = useClerkUser();
  return { isLoaded, isSignedIn, user };
}

// Hook for organization data
export function useOrganization() {
  if (!isAuthEnabled()) {
    return {
      isLoaded: true,
      organization: {
        id: "self-hosted",
        name: "Default Organization",
        slug: "default",
        imageUrl: null,
      },
      membership: {
        role: "admin",
      },
    };
  }

  // eslint-disable-next-line react-hooks/rules-of-hooks -- build-time branch via NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY; see header comment.
  const { isLoaded, organization, membership } = useClerkOrg();
  return { isLoaded, organization, membership };
}

// Get auth header for API requests
export async function getAuthHeader(): Promise<Record<string, string>> {
  if (!isAuthEnabled()) {
    return {}; // Self-hosted mode doesn't need auth headers
  }

  // This should be called in a component context where useAuth is available
  // For server components, use auth() from @clerk/nextjs/server
  return {};
}
