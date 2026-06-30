"use client"

import * as React from "react"

import { cn } from "@/lib/utils"

// F200 (M13 Phase D round 3): the F174 role injection added role="tab" /
// role="tablist" / role="tabpanel" + aria-selected but stopped short of
// the WAI-ARIA tabs pattern. Screen readers had no way to map a panel
// back to its trigger (no aria-controls / aria-labelledby), and keyboard
// users could neither use the arrow keys to move between triggers nor
// rely on a roving tabIndex — every trigger was tabIndex={0}, so Tab
// from outside the tablist stopped on every trigger in DOM order, and
// the active trigger was indistinguishable from inactive ones in the
// tab order. This file now wires:
//   - id linkage: Tabs root mints a stable id prefix via useId, exposed
//     via context; TabsTrigger derives `id=${prefix}-trigger-${value}`
//     and `aria-controls=${prefix}-panel-${value}`. TabsContent mirrors.
//   - roving tabIndex: active trigger = 0, inactive = -1, matching the
//     Radix / shadcn default. Tab from outside lands on the active one
//     only.
//   - arrow-key + Home/End nav on TabsList: ArrowLeft/Right (and Up/Down
//     for vertical orientation, opt-in via `orientation="vertical"`)
//     activates the next trigger. Home goes to first, End to last.
//     We use automatic activation (move + activate together) to match
//     Radix's default `activationMode="automatic"`, since the existing
//     callers (search page, project detail) immediately re-render
//     content on activate and would otherwise need a manual Enter.

interface TabsContextType {
  value: string
  onValueChange: (value: string) => void
  idPrefix: string
  orientation: "horizontal" | "vertical"
}

const TabsContext = React.createContext<TabsContextType | undefined>(undefined)

function useTabsContext(component: string) {
  const ctx = React.useContext(TabsContext)
  if (!ctx) throw new Error(`${component} must be used within Tabs`)
  return ctx
}

function triggerIdFor(prefix: string, value: string) {
  return `${prefix}-trigger-${value}`
}

function panelIdFor(prefix: string, value: string) {
  return `${prefix}-panel-${value}`
}

interface TabsProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string
  onValueChange: (value: string) => void
  orientation?: "horizontal" | "vertical"
}

const Tabs = React.forwardRef<HTMLDivElement, TabsProps>(
  ({ className, value, onValueChange, orientation = "horizontal", children, ...props }, ref) => {
    // F200: stable id prefix shared by every trigger + panel. useId is
    // SSR-safe and gives us a hydration-stable string that survives the
    // initial render and re-renders.
    const idPrefix = React.useId()
    return (
      <TabsContext.Provider value={{ value, onValueChange, idPrefix, orientation }}>
        <div ref={ref} className={cn("", className)} {...props}>
          {children}
        </div>
      </TabsContext.Provider>
    )
  }
)
Tabs.displayName = "Tabs"

const TabsList = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, onKeyDown, ...props }, ref) => {
  const ctx = useTabsContext("TabsList")

  // F200 arrow-key navigation. We resolve siblings at keydown time by
  // querying `[role="tab"]` inside the tablist — this avoids having to
  // register triggers explicitly and keeps the shim caller-API stable
  // (no new ref / context plumbing on the trigger side beyond the id
  // context already wired). `:not([disabled])` matches WAI-ARIA — a
  // disabled trigger must be skipped during arrow navigation.
  function handleKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    const list = e.currentTarget
    const triggers = Array.from(
      list.querySelectorAll<HTMLButtonElement>('[role="tab"]:not([disabled])'),
    )
    if (triggers.length === 0) return
    const currentIndex = triggers.findIndex(
      (el) => el === document.activeElement,
    )
    const isHorizontal = ctx.orientation === "horizontal"
    const nextKey = isHorizontal ? "ArrowRight" : "ArrowDown"
    const prevKey = isHorizontal ? "ArrowLeft" : "ArrowUp"

    let nextIndex = -1
    if (e.key === nextKey) {
      nextIndex =
        currentIndex < 0 ? 0 : (currentIndex + 1) % triggers.length
    } else if (e.key === prevKey) {
      nextIndex =
        currentIndex < 0
          ? triggers.length - 1
          : (currentIndex - 1 + triggers.length) % triggers.length
    } else if (e.key === "Home") {
      nextIndex = 0
    } else if (e.key === "End") {
      nextIndex = triggers.length - 1
    } else {
      if (onKeyDown) onKeyDown(e)
      return
    }

    e.preventDefault()
    const nextEl = triggers[nextIndex]
    nextEl.focus()
    const nextValue = nextEl.dataset.tabValue
    if (nextValue) ctx.onValueChange(nextValue)
    if (onKeyDown) onKeyDown(e)
  }

  return (
    <div
      ref={ref}
      role="tablist"
      aria-orientation={ctx.orientation}
      onKeyDown={handleKeyDown}
      className={cn(
        "inline-flex h-10 items-center justify-center rounded-md bg-muted p-1 text-muted-foreground",
        className
      )}
      {...props}
    />
  )
})
TabsList.displayName = "TabsList"

interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string
}

// F174 (M13-1): the previous shim rendered TabsTrigger as a bare
// <button>, which leaked it into `getByRole('button', { name: 'Search' })`
// queries — the search-page CVE/Component tab triggers ("CVE Search" /
// "Component Search") then sat ahead of the actual form submit button
// in DOM order and `.first()` clicked a no-op tab onChange instead of
// the form, hence the M12-1 CVE search specs never fired the search/cve
// API call. Tagging the trigger with role="tab" + the matching aria-*
// state pulls it out of the button role tree (a11y trees collapse
// `role=tab` under tablist, not button) and matches the Radix/shadcn
// shape callers expect. Same posture for TabsContent → role="tabpanel".
const TabsTrigger = React.forwardRef<HTMLButtonElement, TabsTriggerProps>(
  ({ className, value, ...props }, ref) => {
    const ctx = useTabsContext("TabsTrigger")

    const isSelected = ctx.value === value
    const triggerId = triggerIdFor(ctx.idPrefix, value)
    const panelId = panelIdFor(ctx.idPrefix, value)

    return (
      <button
        ref={ref}
        type="button"
        role="tab"
        id={triggerId}
        aria-selected={isSelected}
        aria-controls={panelId}
        // F200: roving tabIndex. Only the active trigger participates in
        // the document's default Tab order; arrow keys reach the others.
        tabIndex={isSelected ? 0 : -1}
        data-state={isSelected ? "active" : "inactive"}
        // F200: TabsList's keydown handler reads this attribute to call
        // onValueChange with the right value. Stored on the DOM (not in
        // a registry) so the handler does not need to keep refs in sync.
        data-tab-value={value}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-sm px-3 py-1.5 text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
          isSelected
            ? "bg-background text-foreground shadow-sm"
            : "hover:bg-background/50",
          className
        )}
        onClick={() => ctx.onValueChange(value)}
        {...props}
      />
    )
  }
)
TabsTrigger.displayName = "TabsTrigger"

interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string
}

const TabsContent = React.forwardRef<HTMLDivElement, TabsContentProps>(
  ({ className, value, ...props }, ref) => {
    const ctx = useTabsContext("TabsContent")

    if (ctx.value !== value) return null

    const triggerId = triggerIdFor(ctx.idPrefix, value)
    const panelId = panelIdFor(ctx.idPrefix, value)

    return (
      <div
        ref={ref}
        role="tabpanel"
        id={panelId}
        aria-labelledby={triggerId}
        // F200: the panel itself is focusable as a single-stop landing
        // for assistive tech so a user that jumps into the panel can
        // then Tab into the panel content. tabIndex={0} is the WAI-ARIA
        // recommendation for tab panels.
        tabIndex={0}
        data-state="active"
        className={cn(
          "mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
          className
        )}
        {...props}
      />
    )
  }
)
TabsContent.displayName = "TabsContent"

export { Tabs, TabsList, TabsTrigger, TabsContent }
