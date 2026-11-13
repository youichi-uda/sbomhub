"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

// F209 (M14-2): the lightweight Tooltip shim used to render the content
// panel as a bare <div> with no ARIA hooks — no `role="tooltip"`, no
// `aria-describedby` linkage from the trigger to the panel. The
// destructive-action callsites (eol-badge, kev-badge, ssvc-badge,
// ticket-status, etc.) all wrap an icon/badge in `<TooltipTrigger asChild>`,
// so screen readers had no way to announce the supplementary information
// the sighted user gets on hover.
//
//   - TooltipContent renders with `role="tooltip"` and an `id` that
//     resolves the trigger's `aria-describedby` reference.
//   - The `tooltipId` is minted with `useId()` in the Tooltip provider
//     and exposed via TooltipContext, so both halves (trigger + content)
//     can attach the same identifier without prop drilling.
//
// Keyboard / touch reachability (after M73): the as-child trigger of every
// callsite is a plain <span> badge (KEV, EOL, SSVC, ticket) or an <h3>, so
// the onFocus handler could never fire — Tab skipped the badge and its
// explanation was hover-only. The trigger now follows the pattern of the
// distro / match HintBadge (distro-match.tsx):
//   - a trigger that is not natively focusable gets tabIndex=0, and a
//     generic one (span / div) role="button" — a heading keeps its role;
//   - the panel stays mounted (hidden while closed), so aria-describedby
//     resolves to its text before the first hover, and an icon-only trigger
//     with no accessible name of its own is labelled by it;
//   - it opens on hover, focus or tap (Enter / Space on a role="button"
//     trigger) and closes on Escape, on leaving the trigger, on a second
//     tap, or on a tap elsewhere. Each way of opening is tracked on its
//     own so leaving with the pointer does not hide what focus opened;
//   - the trigger's own handlers and ARIA references are kept (merged).
//
// Caller API is unchanged: `<Tooltip><TooltipTrigger asChild>...
// </TooltipTrigger><TooltipContent>...</TooltipContent></Tooltip>`.

interface TooltipContextValue {
  open: boolean;
  tooltipId: string;
  rootRef: React.RefObject<HTMLDivElement | null>;
  setHover: (v: boolean) => void;
  setFocus: (v: boolean) => void;
  setTapped: (v: boolean | ((prev: boolean) => boolean)) => void;
  setDismissed: (v: boolean) => void;
  tapped: boolean;
}

const TooltipContext = React.createContext<TooltipContextValue | null>(null);

function TooltipProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

function Tooltip({ children }: { children: React.ReactNode }) {
  const [hover, setHover] = React.useState(false);
  const [focus, setFocus] = React.useState(false);
  const [tapped, setTapped] = React.useState(false);
  const [dismissed, setDismissed] = React.useState(false);
  const open = (hover || focus || tapped) && !dismissed;
  // F209: a stable id for the panel, so the trigger's reference is present
  // before the user hovers / focuses.
  const tooltipId = React.useId();
  const rootRef = React.useRef<HTMLDivElement>(null);

  // Some mobile browsers do not focus a tapped element, so neither blur nor
  // mouseleave fires when the user taps elsewhere: while open, a
  // pointerdown outside the trigger and its panel closes it.
  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      if (rootRef.current && e.target instanceof Node && !rootRef.current.contains(e.target)) {
        setTapped(false);
        setDismissed(true);
      }
    };
    document.addEventListener("pointerdown", onPointerDown, true);
    return () => document.removeEventListener("pointerdown", onPointerDown, true);
  }, [open]);

  const value = React.useMemo(
    () => ({ open, tooltipId, rootRef, setHover, setFocus, setTapped, setDismissed, tapped }),
    [open, tooltipId, tapped],
  );

  return (
    <TooltipContext.Provider value={value}>
      <div ref={rootRef} className="relative inline-block">
        {children}
      </div>
    </TooltipContext.Provider>
  );
}

const NATIVELY_FOCUSABLE = new Set(["a", "button", "input", "select", "textarea", "summary"]);
// Elements whose implicit role is generic: they get role="button" so the
// focus stop is announced, can carry a name, and Enter / Space toggles it.
const GENERIC_TAGS = new Set(["SPAN", "DIV", "I", "B", "SMALL", "STRONG", "EM"]);

/** Whether a React node renders any text of its own (icons render none). */
function hasTextContent(node: React.ReactNode): boolean {
  if (node == null || typeof node === "boolean") return false;
  if (typeof node === "string") return node.trim() !== "";
  if (typeof node === "number" || typeof node === "bigint") return true;
  if (Array.isArray(node)) return node.some(hasTextContent);
  if (React.isValidElement(node)) {
    const props = node.props as { children?: React.ReactNode; "aria-label"?: string };
    if (props["aria-label"]) return true;
    return hasTextContent(props.children);
  }
  // Anything else (a lazy / async node): assume it renders text rather than
  // replace the trigger's own name with the panel.
  return true;
}

type Handler<E> = ((e: E) => void) | undefined;
function chain<E>(theirs: Handler<E>, ours: (e: E) => void) {
  return (e: E) => {
    theirs?.(e);
    ours(e);
  };
}

function joinIds(...ids: (string | undefined)[]) {
  const out = ids.filter(Boolean).join(" ");
  return out === "" ? undefined : out;
}

type TriggerChildProps = {
  ref?: React.Ref<HTMLElement>;
  children?: React.ReactNode;
  tabIndex?: number;
  role?: string;
  "aria-label"?: string;
  "aria-labelledby"?: string;
  "aria-describedby"?: string;
  onPointerEnter?: Handler<React.PointerEvent<HTMLElement>>;
  onPointerLeave?: Handler<React.PointerEvent<HTMLElement>>;
  onFocus?: Handler<React.FocusEvent<HTMLElement>>;
  onBlur?: Handler<React.FocusEvent<HTMLElement>>;
  onTouchEnd?: Handler<React.TouchEvent<HTMLElement>>;
  onClick?: Handler<React.MouseEvent<HTMLElement>>;
  onKeyDown?: Handler<React.KeyboardEvent<HTMLElement>>;
};

function useTriggerProps(theirs: TriggerChildProps, nativelyFocusable: boolean) {
  const context = React.useContext(TooltipContext);
  if (!context) throw new Error("TooltipTrigger must be used within Tooltip");
  const { open, tapped, tooltipId, setHover, setFocus, setTapped, setDismissed } = context;
  // A tap fires touchend and then click; the click must not undo the open.
  const touchOpened = React.useRef(false);

  const toggleTap = () => {
    if (open && tapped) {
      setTapped(false);
      setDismissed(true);
    } else {
      setTapped(true);
      setDismissed(false);
    }
  };

  const hasName = Boolean(theirs["aria-label"] || theirs["aria-labelledby"]) || hasTextContent(theirs.children);

  return {
    tabIndex: theirs.tabIndex ?? (nativelyFocusable ? undefined : 0),
    // An icon-only trigger is named by the panel; otherwise the panel is
    // its description. Either reference is set whether or not it is open.
    "aria-labelledby": hasName ? theirs["aria-labelledby"] : joinIds(theirs["aria-labelledby"], tooltipId),
    "aria-describedby": hasName ? joinIds(theirs["aria-describedby"], tooltipId) : theirs["aria-describedby"],
    "data-tooltip-trigger": "",
    // Hover is a mouse / pen thing. A tap is followed by compatibility
    // mouseenter / mouseleave events, which reopened a tooltip the tap had
    // just closed (Codex R2 Low-2, seen with real taps); pointer events say
    // which device they came from.
    onPointerEnter: chain(theirs.onPointerEnter, (e: React.PointerEvent<HTMLElement>) => {
      if (e.pointerType === "touch") return;
      setHover(true);
      setDismissed(false);
    }),
    onPointerLeave: chain(theirs.onPointerLeave, (e: React.PointerEvent<HTMLElement>) => {
      if (e.pointerType === "touch") return;
      setHover(false);
      setTapped(false);
    }),
    onFocus: chain(theirs.onFocus, () => {
      setFocus(true);
      setDismissed(false);
    }),
    onBlur: chain(theirs.onBlur, () => {
      setFocus(false);
      setTapped(false);
    }),
    // touchend is the tap on a touch screen (some mobile browsers send no
    // click to a non-interactive element); the click that follows it is
    // skipped so one tap toggles once.
    onTouchEnd: (e: React.TouchEvent<HTMLElement>) => {
      theirs.onTouchEnd?.(e);
      touchOpened.current = true;
      toggleTap();
    },
    onClick: (e: React.MouseEvent<HTMLElement>) => {
      theirs.onClick?.(e);
      if (touchOpened.current) {
        touchOpened.current = false;
        return;
      }
      toggleTap();
    },
    onKeyDown: chain(theirs.onKeyDown, (e: React.KeyboardEvent<HTMLElement>) => {
      if (e.key === "Escape") {
        if (open) e.stopPropagation();
        setTapped(false);
        setDismissed(true);
        return;
      }
      // A role="button" trigger (a span, not a real button, which turns them
      // into a click itself): Enter / Space do what a click does.
      if ((e.key === "Enter" || e.key === " ") && e.currentTarget.getAttribute("role") === "button") {
        e.preventDefault();
        toggleTap();
      }
    }),
  };
}

/** Gives a generic element (span / div) role="button"; a heading keeps its role. */
function useGenericRole(ref: React.RefObject<HTMLElement | null>, explicitRole: string | undefined) {
  React.useLayoutEffect(() => {
    const el = ref.current;
    if (!el || explicitRole !== undefined) return;
    if (GENERIC_TAGS.has(el.tagName) && !el.hasAttribute("role")) {
      el.setAttribute("role", "button");
    }
  });
}

/** Sets a ref; returns a React 19 callback ref's cleanup, if it gave one. */
function setRef<T>(ref: React.Ref<T> | undefined, value: T | null): void | (() => void) {
  if (typeof ref === "function") {
    const cleanup = ref(value);
    return typeof cleanup === "function" ? cleanup : undefined;
  }
  if (ref && typeof ref === "object") (ref as React.RefObject<T | null>).current = value;
}

function TooltipTrigger({
  children,
  asChild,
}: {
  children: React.ReactNode;
  asChild?: boolean;
}) {
  const asChildElement =
    asChild && React.isValidElement(children) ? (children as React.ReactElement<TriggerChildProps>) : null;
  const theirs: TriggerChildProps = asChildElement ? asChildElement.props : { children };
  const nativelyFocusable =
    asChildElement !== null && typeof asChildElement.type === "string" && NATIVELY_FOCUSABLE.has(asChildElement.type);
  const props = useTriggerProps(theirs, nativelyFocusable);
  const nodeRef = React.useRef<HTMLElement | null>(null);
  useGenericRole(nodeRef, theirs.role);

  const theirRef = theirs.ref;
  const ref = React.useCallback(
    (node: HTMLElement) => {
      nodeRef.current = node;
      const cleanup = setRef(theirRef, node);
      // React 19: returning a cleanup means React calls it instead of the
      // ref with null — so the trigger's own cleanup (or its null call)
      // must happen here (Codex R1 Low-4).
      return () => {
        nodeRef.current = null;
        if (cleanup) cleanup();
        else setRef(theirRef, null);
      };
    },
    [theirRef],
  );

  if (asChildElement) {
    return React.cloneElement(asChildElement, { ...props, ref } as Partial<TriggerChildProps>);
  }

  return (
    <span {...props} ref={ref} role="button">
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
  const ref = React.useRef<HTMLDivElement>(null);
  const open = context.open;

  // The panel is centred on its trigger with CSS only; near a viewport edge
  // (a phone-width screen) it would run off-screen (Codex M73 R1 Medium-1).
  // After layout, cap its width to the viewport and shift it back inside,
  // with an 8px inset.
  // Re-run on resize / rotation while open (Codex M73 R2 Low-1).
  React.useLayoutEffect(() => {
    const el = ref.current;
    if (!open || !el) return;
    const clamp = () => {
      const inset = 8;
      el.style.marginLeft = "";
      el.style.maxWidth = "";
      const vw = document.documentElement.clientWidth;
      if (el.getBoundingClientRect().width > vw - 2 * inset) {
        el.style.maxWidth = `${vw - 2 * inset}px`;
      }
      const rect = el.getBoundingClientRect();
      const shift =
        rect.left < inset ? inset - rect.left : rect.right > vw - inset ? vw - inset - rect.right : 0;
      if (shift !== 0) el.style.marginLeft = `${shift}px`;
    };
    clamp();
    window.addEventListener("resize", clamp);
    return () => window.removeEventListener("resize", clamp);
  }, [open]);

  const positionClasses = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
  };

  return (
    <div
      ref={ref}
      // F209: `role="tooltip"` + the shared `id` complete the WAI-ARIA
      // tooltip contract started by the trigger's `aria-describedby`.
      // Mounted while closed (hidden) so that reference — and the label of
      // an icon-only trigger — resolves before the first hover / focus.
      role="tooltip"
      id={context.tooltipId}
      hidden={!open}
      className={cn(
        // w-max + max-w-xs: the panel is positioned inside the trigger's
        // inline-block wrapper, so without an explicit width it shrank to
        // the badge's width and wrapped every word. The former
        // `animate-in fade-in-0 zoom-in-95` came from tailwindcss-animate,
        // which was never installed, and generated nothing.
        "absolute z-50 w-max max-w-xs overflow-hidden rounded-md border bg-popover px-3 py-1.5 text-sm text-popover-foreground shadow-md",
        positionClasses[side],
        className
      )}
    >
      {children}
    </div>
  );
}

export { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider };
