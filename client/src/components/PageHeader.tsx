import type { ReactNode } from "react";

/**
 * Standard page header — preview spec:
 *   title       20px / 700 / -0.02em
 *   description 14px / muted, line-height 1.55
 *   eyebrow     11px / 600 / 0.14em / uppercase / brand (optional)
 *
 * Use `eyebrow` for product-area context ("Threat intelligence",
 * "Inventory & evidence") — it gives every page a consistent
 * Stripe/Linear-style mini-breadcrumb without crowding the title.
 */
export function PageHeader({
  title,
  description,
  eyebrow,
  actions,
}: {
  title: string;
  description?: string;
  eyebrow?: string;
  actions?: ReactNode;
}) {
  const slug = title.toLowerCase().replace(/\s+/g, "-");
  return (
    <div className="os-page-header flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3 lg:gap-6 mb-8">
      <div className="min-w-0 space-y-1">
        {eyebrow && (
          <div className="os-eyebrow" data-testid={`eyebrow-${slug}`}>
            {eyebrow}
          </div>
        )}
        <h1
          className="os-page-title"
          data-testid={`heading-${slug}`}
        >
          {title}
        </h1>
        {description && (
          <p className="text-sm text-muted-foreground leading-[1.55] max-w-3xl">
            {description}
          </p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2 lg:shrink-0 flex-wrap">
          {actions}
        </div>
      )}
    </div>
  );
}
