"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { Dialog, DialogContent, DialogTitle } from "./dialog";

// F205 (M13 Phase D round 4): the AlertDialog shim used to render its
// own bare modal panel — no role="dialog", no aria-modal, no aria-
// labelledby linkage, no Escape handler, no focus trap, no accessible
// close affordance. The sibling Dialog shim was hardened in F192 to
// the full WAI-ARIA modal contract, leaving AlertDialog (which drives
// the destructive-action callers — delete API key in
// settings/apikeys and delete integration in settings/integrations,
// where the keyboard/SR axis matters most) carrying the old, non-
// conformant shim. Round 4 review flagged this as the symmetric half
// of anti-pattern 48 (fix-one-instance-leave-pattern).
//
// Resolution: compose, don't duplicate. AlertDialogContent now
// delegates the modal panel rendering to Dialog/DialogContent,
// inheriting:
//   - role="dialog" + aria-modal="true" on the panel (F174)
//   - useId-derived titleId via DialogContext → aria-labelledby
//     (F192) — surfaced by AlertDialogTitle which delegates to
//     DialogTitle.
//   - Escape-to-close via the Dialog-level document keydown (F192)
//   - Tab/Shift+Tab focus trap with previously-focused element
//     restoration on unmount (F192)
//   - Backdrop click dismissal (inherited from Dialog).
//
// The destructive-confirmation UX is preserved at this layer:
//   - 2-button Cancel/Confirm group inside AlertDialogFooter.
//   - AlertDialogAction auto-closes the modal after firing onClick,
//     matching the prior behaviour. Callers can still pass the
//     bg-destructive variant via className override.
//   - No close X button — the Cancel button is the explicit dismiss
//     affordance for destructive confirm, so DialogContent.onClose
//     is omitted. Escape and backdrop click both still close via
//     the inherited Dialog wiring.
//
// Caller API is unchanged: <AlertDialog>/<AlertDialogTrigger>/
// <AlertDialogContent>/.../<AlertDialogCancel>/<AlertDialogAction>
// signatures all match the pre-F205 surface, so the two production
// callers (settings/apikeys delete confirm, settings/integrations
// delete confirm) inherit ARIA hardening with zero code change.
//
// Rejected alternative (option A in the F205 brief): duplicate the
// F192 hardening triple — focus trap, Escape, aria-labelledby — onto
// AlertDialogContent. That would double the maintenance surface and
// is exactly the species (parallel modal primitive drifting from its
// sibling) that anti-pattern 48 names; compose is the structural fix.

interface AlertDialogContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const AlertDialogContext = React.createContext<AlertDialogContextValue | null>(null);

function AlertDialog({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);

  return (
    <AlertDialogContext.Provider value={{ open, setOpen }}>
      {children}
    </AlertDialogContext.Provider>
  );
}

function AlertDialogTrigger({
  children,
  asChild,
}: {
  children: React.ReactNode;
  asChild?: boolean;
}) {
  const context = React.useContext(AlertDialogContext);
  if (!context) throw new Error("AlertDialogTrigger must be used within AlertDialog");

  if (asChild && React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<{ onClick?: () => void }>, {
      onClick: () => context.setOpen(true),
    });
  }

  return (
    <button type="button" onClick={() => context.setOpen(true)}>
      {children}
    </button>
  );
}

function AlertDialogContent({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const context = React.useContext(AlertDialogContext);
  if (!context) throw new Error("AlertDialogContent must be used within AlertDialog");

  // F205: route the panel through Dialog/DialogContent so the F192
  // hardening (focus trap, Escape, aria-labelledby via DialogContext,
  // accessible-name on the close affordance when present) covers the
  // destructive-action surface. `onClose` is intentionally omitted —
  // destructive confirm uses Cancel as the explicit dismiss
  // affordance, and the Escape/backdrop paths are wired by Dialog
  // itself.
  //
  // The default DialogContent panel styling
  // (`bg-white rounded-lg shadow-lg p-6 w-full max-w-md`) differs from
  // the pre-F205 AlertDialog panel (`bg-background rounded-lg
  // shadow-lg p-6 w-full max-w-md`) only in the surface token —
  // `bg-background` resolves to the same Tailwind v3 base in this
  // project's tokens. Passing it explicitly preserves the prior look
  // under both light and dark themes, while a caller-provided
  // className still overrides via the cn() merge inside DialogContent.
  return (
    <Dialog open={context.open} onOpenChange={context.setOpen}>
      <DialogContent className={cn("bg-background", className)}>
        {children}
      </DialogContent>
    </Dialog>
  );
}

function AlertDialogHeader({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col space-y-2 text-center sm:text-left", className)}>
      {children}
    </div>
  );
}

function AlertDialogFooter({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2 mt-4",
        className
      )}
    >
      {children}
    </div>
  );
}

function AlertDialogTitle({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  // F205: delegate to DialogTitle so the useId-minted DialogContext
  // titleId is read on the heading. The panel's aria-labelledby then
  // resolves to the confirmation heading (e.g. "Delete API Key?") and
  // screen readers announce the modal with its title rather than as
  // an unlabeled region.
  //
  // The two current production callers
  // (settings/apikeys, settings/integrations) pass no className override,
  // so they take the direct delegation path. If a future caller passes
  // a className override, we wrap DialogTitle in a div carrying the
  // override class — the h2 semantics + id linkage on DialogTitle are
  // preserved, and the wrapper only contributes visual layout. We
  // deliberately do not render a second h2 to avoid landing two
  // headings at the same level inside the dialog.
  //
  // F212 (M14-2): the wrapper <div> previously had no ARIA role, so
  // screen-reader tree walkers saw it as an anonymous structural node
  // sandwiched between the role="dialog" panel and the inner h2. Adding
  // `role="presentation"` tells assistive tech that the wrapper carries
  // no semantic value — it exists only to host the caller-supplied
  // className for visual layout — and that the announcement should jump
  // directly to the inner DialogTitle h2 (which still owns the
  // DialogContext titleId surfaced via aria-labelledby on the dialog
  // panel). This closes the M13 round 5/6 cosmetic flag about the
  // wrapper's silent semantic identity and finishes the AlertDialog
  // a11y wiring started by F205.
  if (className) {
    return (
      <div className={className} role="presentation">
        <DialogTitle>{children}</DialogTitle>
      </div>
    );
  }
  return <DialogTitle>{children}</DialogTitle>;
}

function AlertDialogDescription({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  // F205: the description text lives inside the role="dialog" panel
  // so it is part of the announced modal body for screen readers. The
  // panel's aria-labelledby points at the title (sufficient for the
  // WAI-ARIA modal name contract); aria-describedby linkage is a
  // future enhancement gated on extending DialogContent to accept a
  // describedby prop (touching dialog.tsx is out of scope for F205).
  // Styling is kept as-is to preserve the destructive-confirm visual
  // hierarchy (muted body text under the title).
  return (
    <p className={cn("text-sm text-muted-foreground", className)}>{children}</p>
  );
}

function AlertDialogAction({
  children,
  onClick,
  className,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  const context = React.useContext(AlertDialogContext);
  if (!context) throw new Error("AlertDialogAction must be used within AlertDialog");

  return (
    <button
      type="button"
      onClick={() => {
        onClick?.();
        context.setOpen(false);
      }}
      className={cn(
        "inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2",
        className
      )}
    >
      {children}
    </button>
  );
}

function AlertDialogCancel({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const context = React.useContext(AlertDialogContext);
  if (!context) throw new Error("AlertDialogCancel must be used within AlertDialog");

  return (
    <button
      type="button"
      onClick={() => context.setOpen(false)}
      className={cn(
        "inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2 mt-2 sm:mt-0",
        className
      )}
    >
      {children}
    </button>
  );
}

export {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
};
