import { notFound } from "next/navigation";

// M71: an unknown path under a locale renders the 404 page inside the
// [locale] layout, on demand, so Next.js puts this request's CSP nonce on
// its scripts. Without this route Next serves its build-time /_not-found
// page, whose inline scripts carry no nonce and are blocked by the CSP
// (the page text still showed, but nothing on it ran).
export default function CatchAllNotFound() {
  notFound();
}
