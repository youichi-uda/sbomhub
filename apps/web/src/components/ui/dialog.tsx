"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { X } from "lucide-react";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
}

export function Dialog({ open, onOpenChange, children }: DialogProps) {
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

export function DialogContent({
  className,
  children,
  onClose,
}: {
  className?: string;
  children: React.ReactNode;
  onClose?: () => void;
}) {
  // F174 (M13-1): expose the WAI-ARIA modal role on the panel itself.
  // The original shim rendered raw <div>s with no role, so anything
  // scoping by `[role="dialog"]` (assistive-tech focus traps, Playwright
  // selectors in security.spec.ts and integrations.spec.ts) could not
  // locate the panel — security.spec.ts:363 hit a 60 s timeout chasing
  // the in-dialog Create button. Adding role + aria-modal also lets
  // screen readers announce the panel as a modal rather than an
  // unlabeled region. The class set is unchanged so positioning, sizing,
  // and the dark-mode shadow remain identical.
  return (
    <div
      role="dialog"
      aria-modal="true"
      className={cn("bg-white rounded-lg shadow-lg p-6 w-full max-w-md", className)}
    >
      {onClose && (
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-gray-400 hover:text-gray-600"
        >
          <X className="h-4 w-4" />
        </button>
      )}
      {children}
    </div>
  );
}

export function DialogHeader({ children }: { children: React.ReactNode }) {
  return <div className="mb-4">{children}</div>;
}

export function DialogTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="text-lg font-semibold">{children}</h2>;
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
