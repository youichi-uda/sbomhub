"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "destructive";
}

const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ className, variant = "default", ...props }, ref) => (
    <div
      ref={ref}
      role="alert"
      className={cn(
        "relative w-full rounded-lg border p-4",
        variant === "default" && "bg-background text-foreground",
        variant === "destructive" &&
          "border-destructive/50 text-destructive dark:border-destructive [&>svg]:text-destructive",
        className
      )}
      {...props}
    />
  )
);
Alert.displayName = "Alert";

const AlertTitle = React.forwardRef<
  HTMLHeadingElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
  <h5
    ref={ref}
    className={cn("mb-1 font-medium leading-none tracking-tight", className)}
    {...props}
  />
));
AlertTitle.displayName = "AlertTitle";

// F210 (M14-2): the forwardRef previously declared
// `HTMLParagraphElement` on both the ref and prop generics while the
// JSX rendered a `<div>` — a type-vs-DOM mismatch that meant `ref`
// typed at the callsite was `RefObject<HTMLParagraphElement>` but
// actually pointed at an `HTMLDivElement`, and `<p>`-only attributes
// would have type-checked but silently no-op'd at runtime. The render
// must stay as `<div>` because production callers nest block-level
// children (icon + flex layout in triage/ai-disabled-banner; multi-`<p>`
// content elsewhere) which would be invalid HTML nesting inside a `<p>`
// — `<p>` cannot contain `<div>` per the HTML spec and the React
// hydration warning surfaces it loudly. The `[&_p]:leading-relaxed`
// utility class targeting *nested* `<p>` children is preserved.
// Resolution: align both ref and prop generics to `HTMLDivElement` so
// the type surface matches the rendered element. Caller-supplied
// `ref={...}` now narrows correctly and div-only attrs become available.
const AlertDescription = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("text-sm [&_p]:leading-relaxed", className)}
    {...props}
  />
));
AlertDescription.displayName = "AlertDescription";

export { Alert, AlertTitle, AlertDescription };
