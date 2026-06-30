"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { X } from "lucide-react";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

// F192 (M13 Phase D round 3): the WAI-ARIA modal contract that F174
// half-introduced — role="dialog" + aria-modal="true" on the panel —
// was missing focus trap, Escape-to-close, accessible-name linkage,
// and an accessible-name on the close affordance. F174's commit
// message overclaimed "matches the WAI-ARIA modal role" which only
// describes the role attribute story; assistive-tech focus traps and
// keyboard-only operators still escaped the modal on Tab and could not
// dismiss it without a mouse. This file now completes the contract by:
//   - DialogTitle id linkage: DialogContent mints a useId() and exposes
//     it via DialogContext, DialogTitle reads it and lands aria-labelledby.
//   - Focus trap: DialogContent grabs focusable elements on mount, focuses
//     the first one, and cycles Tab / Shift+Tab inside the modal panel.
//   - Escape handler: top-level Dialog wraps a document keydown listener
//     that fires onOpenChange(false). Backdrop click stays as the existing
//     close affordance.
//   - Close button aria-label: the X button surfaces the Common.close
//     translation as its accessible name. A `closeLabel` prop is exposed
//     so callers that mount via a server-rendered translation pass the
//     localised string in; the shim keeps a sensible "Close" fallback.

interface DialogContextValue {
  titleId: string;
}

const DialogContext = React.createContext<DialogContextValue | null>(null);

export function Dialog({ open, onOpenChange, children }: DialogProps) {
  // F192: Escape key must dismiss the modal. We listen at the document
  // level (not at DialogContent) because focus may be on the backdrop
  // or briefly outside the trapped surface between renders, and the
  // keyboard-only operator still expects Escape to close.
  React.useEffect(() => {
    if (!open) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        onOpenChange(false);
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, onOpenChange]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div className="fixed inset-0 bg-black/50" onClick={() => onOpenChange(false)} />
      <div className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50">
        {children}
      </div>
    </div>
  );
}

// Focusable-element selector matching common form / nav controls. The
// `tabindex` predicate excludes `-1` (programmatic-only focus) so the
// trap walks only the keyboard-reachable surface.
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

export function DialogContent({
  className,
  children,
  onClose,
  closeLabel = "Close",
  "aria-labelledby": ariaLabelledByProp,
  "aria-label": ariaLabelProp,
}: {
  className?: string;
  children: React.ReactNode;
  onClose?: () => void;
  closeLabel?: string;
  "aria-labelledby"?: string;
  "aria-label"?: string;
}) {
  // F174: role + aria-modal on the panel itself (kept).
  // F192: useId-derived titleId is provided to DialogTitle via context
  // so screen readers announce the dialog with its title rather than as
  // an unlabeled region. If the caller passed aria-labelledby explicitly
  // (e.g. titling a panel without a DialogTitle child), we honour it.
  const generatedTitleId = React.useId();
  const titleId = ariaLabelledByProp || generatedTitleId;
  const dialogRef = React.useRef<HTMLDivElement | null>(null);

  // F192 focus trap: on mount, focus the first focusable element inside
  // the panel. The previously-focused element is restored on unmount so
  // the operator returns to where they triggered the modal. We capture
  // `document.activeElement` at mount time rather than at unmount time
  // because the trap itself moves focus.
  React.useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const panel = dialogRef.current;
    if (!panel) return;
    const focusables = panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
    // Prefer an element marked `autoFocus` if present, otherwise focus
    // the first focusable element so keyboard nav lands inside the modal.
    const autoFocus = panel.querySelector<HTMLElement>("[autofocus]");
    const initial = autoFocus ?? focusables[0] ?? panel;
    // Ensure the panel itself is focusable as a last-resort fallback so
    // screen readers can still announce the dialog when it contains no
    // interactive children (e.g. confirmation-only).
    if (initial === panel) {
      panel.tabIndex = -1;
    }
    initial?.focus();
    return () => {
      previouslyFocused?.focus?.();
    };
  }, []);

  // F192 Tab cycling: keep keyboard focus inside the modal. We intercept
  // Tab / Shift+Tab on the panel and rewrap focus to the opposite end.
  // We do NOT intercept other keys — Escape is handled at the Dialog
  // level, arrow keys etc. belong to the content.
  function handleKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (e.key !== "Tab") return;
    const panel = dialogRef.current;
    if (!panel) return;
    const focusables = Array.from(
      panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
    ).filter((el) => el.offsetParent !== null || el === document.activeElement);
    if (focusables.length === 0) {
      e.preventDefault();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (e.shiftKey) {
      if (active === first || !panel.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last || !panel.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  return (
    <DialogContext.Provider value={{ titleId }}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ariaLabelProp ? undefined : titleId}
        aria-label={ariaLabelProp}
        onKeyDown={handleKeyDown}
        className={cn("relative bg-white rounded-lg shadow-lg p-6 w-full max-w-md", className)}
      >
        {children}
        {/* F192: close button rendered AFTER {children} so the initial
            focusable lookup in the panel lands on the first content
            input/button rather than the X. The X is `position: absolute`
            so visual placement is unaffected by DOM order. */}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label={closeLabel}
            className="absolute right-4 top-4 text-gray-400 hover:text-gray-600"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    </DialogContext.Provider>
  );
}

export function DialogHeader({ children }: { children: React.ReactNode }) {
  return <div className="mb-4">{children}</div>;
}

export function DialogTitle({ children }: { children: React.ReactNode }) {
  // F192: consume the titleId minted by DialogContent so the panel's
  // aria-labelledby reference resolves to this heading. When DialogTitle
  // is rendered outside a DialogContent the id falls back to undefined,
  // matching pre-F192 behaviour for any (currently none) standalone use.
  const ctx = React.useContext(DialogContext);
  return (
    <h2 id={ctx?.titleId} className="text-lg font-semibold">
      {children}
    </h2>
  );
}

export function DialogFooter({ children }: { children: React.ReactNode }) {
  return <div className="mt-6 flex justify-end gap-2">{children}</div>;
}

export function DialogDescription({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-gray-500 mt-1">{children}</p>;
}

export function DialogTrigger({
  children,
  // `asChild` is kept on the public type to match the shadcn/Radix
  // surface (callers commonly pass `<DialogTrigger asChild>`), even
  // though this minimal shim does not apply Slot-style merging.
  asChild: _asChild,
}: {
  children: React.ReactNode;
  asChild?: boolean;
}) {
  // Simple pass-through - the trigger is handled by the parent
  return <>{children}</>;
}
