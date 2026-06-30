"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

// F209 (M14-2): the lightweight Tooltip shim used to render the content
// panel as a bare <div> with no ARIA hooks — no `role="tooltip"`, no
// `aria-describedby` linkage from the trigger to the panel. The
// destructive-action callsites (eol-badge, kev-badge, ssvc-badge,
// ticket-status, etc.) all wrap an icon/badge in `<TooltipTrigger asChild>`,
// so screen readers had no way to announce the supplementary information
// the sighted user gets on hover. M13 round 5/6 flagged this as the
// cosmetic-class residue of anti-pattern 48 (fix-one-instance-leave-pattern)
// after Dialog (F192) / Tabs (F200) / AlertDialog (F205) had been
// hardened, leaving Tooltip as the last primitive without ARIA wiring.
//
// Resolution:
//   - TooltipContent renders with `role="tooltip"` and an `id` that
//     resolves the trigger's `aria-describedby` reference.
//   - The `tooltipId` is minted with `useId()` in the Tooltip provider
//     and exposed via TooltipContext, so both halves (trigger + content)
//     can attach the same identifier without prop drilling.
//   - The id is set on the trigger **regardless** of `context.open` so
//     the screen-reader association is present before the user hovers /
//     focuses (matches the SR + tooltip contract: the describedby
//     reference can dangle when the content is unmounted; SRs handle
//     the missing target gracefully and the reference becomes live the
//     moment hover/focus opens the panel).
//   - Trigger also opens on `focus` (keyboard nav) and `touchend`
//     (mobile / touch-screen a11y), not just `mouseenter`. This keeps
//     keyboard-only and touch operators on the same SR contract.
//
// Caller API is preserved: the 8+ existing callsites
// (eol-badge / kev-badge / ssvc-badge / ticket-status / etc.) keep the
// `<Tooltip><TooltipTrigger asChild>...</TooltipTrigger><TooltipContent>
// ...</TooltipContent></Tooltip>` structure and inherit the ARIA wiring
// with zero code change.

interface TooltipContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
  tooltipId: string;
}

const TooltipContext = React.createContext<TooltipContextValue | null>(null);

function TooltipProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

function Tooltip({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  // F209: mint a stable id for the tooltip panel up-front so the
  // trigger's `aria-describedby` reference is stable across re-renders
  // and the SR association is present before the user hovers/focuses.
  const tooltipId = React.useId();

  const value = React.useMemo(
    () => ({ open, setOpen, tooltipId }),
    [open, tooltipId],
  );

  return (
    <TooltipContext.Provider value={value}>
      <div className="relative inline-block">{children}</div>
    </TooltipContext.Provider>
  );
}

function TooltipTrigger({
  children,
  asChild,
}: {
  children: React.ReactNode;
  asChild?: boolean;
}) {
  const context = React.useContext(TooltipContext);
  if (!context) throw new Error("TooltipTrigger must be used within Tooltip");

  const handleOpen = () => context.setOpen(true);
  const handleClose = () => context.setOpen(false);

  if (asChild && React.isValidElement(children)) {
    // F209: merge our ARIA + handlers onto the as-child element. We
    // always set `aria-describedby` (not gated on open) so the SR
    // association is present before hover/focus. `onFocus` covers
    // keyboard-only operators; `onTouchEnd` covers mobile / touch
    // surfaces that don't fire `mouseenter`.
    return React.cloneElement(
      children as React.ReactElement<{
        "aria-describedby"?: string;
        onMouseEnter?: () => void;
        onMouseLeave?: () => void;
        onFocus?: () => void;
        onBlur?: () => void;
        onTouchEnd?: () => void;
      }>,
      {
        "aria-describedby": context.tooltipId,
        onMouseEnter: handleOpen,
        onMouseLeave: handleClose,
        onFocus: handleOpen,
        onBlur: handleClose,
        onTouchEnd: handleOpen,
      },
    );
  }

  return (
    <span
      aria-describedby={context.tooltipId}
      tabIndex={0}
      onMouseEnter={handleOpen}
      onMouseLeave={handleClose}
      onFocus={handleOpen}
      onBlur={handleClose}
      onTouchEnd={handleOpen}
    >
      {children}
    </span>
  );
}

function TooltipContent({
  children,
  className,
  side = "top",
  // `sideOffset` is preserved on the public type for shadcn/Radix API
  // parity; this lightweight tooltip uses Tailwind margins for spacing
  // instead of a numeric offset prop.
  sideOffset: _sideOffset = 4,
}: {
  children: React.ReactNode;
  className?: string;
  side?: "top" | "right" | "bottom" | "left";
  sideOffset?: number;
}) {
  const context = React.useContext(TooltipContext);
  if (!context) throw new Error("TooltipContent must be used within Tooltip");

  if (!context.open) return null;

  const positionClasses = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
  };

  return (
    <div
      // F209: `role="tooltip"` + the shared `id` complete the WAI-ARIA
      // tooltip contract started by the trigger's `aria-describedby`.
      role="tooltip"
      id={context.tooltipId}
      className={cn(
        "absolute z-50 overflow-hidden rounded-md border bg-popover px-3 py-1.5 text-sm text-popover-foreground shadow-md animate-in fade-in-0 zoom-in-95",
        positionClasses[side],
        className
      )}
    >
      {children}
    </div>
  );
}

export { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider };
