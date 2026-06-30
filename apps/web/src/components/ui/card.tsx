import * as React from "react";
import { cn } from "@/lib/utils";

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("rounded-lg border bg-card text-card-foreground shadow-sm", className)}
      {...props}
    />
  )
);
Card.displayName = "Card";

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("flex flex-col space-y-1.5 p-6", className)} {...props} />
  )
);
CardHeader.displayName = "CardHeader";

// F211 (M14-2): the forwardRef previously typed its ref as
// `HTMLParagraphElement` while the props generic and the rendered
// element were `HTMLHeadingElement` (<h3>). That asymmetry meant a
// caller's `ref={ref}` was typed `RefObject<HTMLParagraphElement>` but
// actually pointed at an `HTMLHeadingElement`, defeating ref-narrowing
// and breaking IntelliSense on any heading-only DOM method
// (e.g. `node.scrollIntoView({ block: "center" })` type-checks on both
// so is fine, but heading-specific role probing was lost).
// Resolution: unify both generics to `HTMLHeadingElement`. The render
// stays as `<h3>` — callers (page hero, draft-card, report-card,
// criterion-card, etc.) all rely on the h3 default and none pass an
// `as`-prop override (grep-verified during M14-2 audit). CardDescription
// below already has symmetric `HTMLParagraphElement` generics and is
// unchanged.
const CardTitle = React.forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h3 ref={ref} className={cn("text-2xl font-semibold leading-none tracking-tight", className)} {...props} />
  )
);
CardTitle.displayName = "CardTitle";

const CardDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <p ref={ref} className={cn("text-sm text-muted-foreground", className)} {...props} />
  )
);
CardDescription.displayName = "CardDescription";

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("p-6 pt-0", className)} {...props} />
  )
);
CardContent.displayName = "CardContent";

export { Card, CardHeader, CardTitle, CardDescription, CardContent };
