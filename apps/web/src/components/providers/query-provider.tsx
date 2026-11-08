"use client";

import { QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { makeQueryClient } from "@/lib/query/client";

// One QueryClient per browser session (lazy useState initialiser, so a
// re-render never swaps the cache out from under mounted queries). See
// src/lib/query/client.ts for why the defaults differ from react-query's.
export function QueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(makeQueryClient);
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
