"use client"

import * as React from "react"
import { ChevronDown } from "lucide-react"

import { cn } from "@/lib/utils"

interface AccordionContextType {
  value: string[]
  onValueChange: (value: string[]) => void
  type: "single" | "multiple"
}

const AccordionContext = React.createContext<AccordionContextType | undefined>(undefined)

interface AccordionProps extends React.HTMLAttributes<HTMLDivElement> {
  type?: "single" | "multiple"
  value?: string[]
  defaultValue?: string[]
  onValueChange?: (value: string[]) => void
}

const Accordion = React.forwardRef<HTMLDivElement, AccordionProps>(
  ({ className, type = "single", value, defaultValue = [], onValueChange, children, ...props }, ref) => {
    const [internalValue, setInternalValue] = React.useState<string[]>(defaultValue)
    const currentValue = value ?? internalValue

    const handleValueChange = (newValue: string[]) => {
      setInternalValue(newValue)
      onValueChange?.(newValue)
    }

    return (
      <AccordionContext.Provider value={{ value: currentValue, onValueChange: handleValueChange, type }}>
        <div ref={ref} className={cn("", className)} {...props}>
          {children}
        </div>
      </AccordionContext.Provider>
    )
  }
)
Accordion.displayName = "Accordion"

interface AccordionItemProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string
}

const AccordionItemContext = React.createContext<{ value: string } | undefined>(undefined)

const AccordionItem = React.forwardRef<HTMLDivElement, AccordionItemProps>(
  ({ className, value, ...props }, ref) => (
    <AccordionItemContext.Provider value={{ value }}>
      <div ref={ref} className={cn("border-b", className)} {...props} />
    </AccordionItemContext.Provider>
  )
)
AccordionItem.displayName = "AccordionItem"

const AccordionTrigger = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement>
>(({ className, children, ...props }, ref) => {
  const accordionContext = React.useContext(AccordionContext)
  const itemContext = React.useContext(AccordionItemContext)

  if (!accordionContext || !itemContext) {
    throw new Error("AccordionTrigger must be used within Accordion and AccordionItem")
  }

  const isOpen = accordionContext.value.includes(itemContext.value)

  const handleClick = () => {
    if (accordionContext.type === "single") {
      accordionContext.onValueChange(isOpen ? [] : [itemContext.value])
    } else {
      if (isOpen) {
        accordionContext.onValueChange(accordionContext.value.filter(v => v !== itemContext.value))
      } else {
        accordionContext.onValueChange([...accordionContext.value, itemContext.value])
      }
    }
  }

  return (
    <button
      ref={ref}
      className={cn(
        "flex flex-1 items-center justify-between py-4 font-medium transition-all hover:underline [&[data-state=open]>svg]:rotate-180",
        className
      )}
      onClick={handleClick}
      data-state={isOpen ? "open" : "closed"}
      {...props}
    >
      {children}
      <ChevronDown className={cn("h-4 w-4 shrink-0 transition-transform duration-200", isOpen && "rotate-180")} />
    </button>
  )
})
AccordionTrigger.displayName = "AccordionTrigger"

const AccordionContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => {
  const accordionContext = React.useContext(AccordionContext)
  const itemContext = React.useContext(AccordionItemContext)

  if (!accordionContext || !itemContext) {
    throw new Error("AccordionContent must be used within Accordion and AccordionItem")
  }

  const isOpen = accordionContext.value.includes(itemContext.value)

  if (!isOpen) return null

  return (
    <div
      ref={ref}
      className={cn("overflow-hidden text-sm transition-all", className)}
      {...props}
    >
      <div className="pb-4 pt-0">{children}</div>
    </div>
  )
})
AccordionContent.displayName = "AccordionContent"

export { Accordion, AccordionItem, AccordionTrigger, AccordionContent }
