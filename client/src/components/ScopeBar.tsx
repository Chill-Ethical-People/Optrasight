import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Network, Building2, Briefcase, Globe2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export type ScopeDimension = "client" | "industry" | "geo";

export interface ScopeGroup {
  id: string;
  label: string;
  tenantIds: string[];
}

export interface GlobalGroupsResponse {
  client: ScopeGroup[];
  industry: ScopeGroup[];
  geo: ScopeGroup[];
}

interface ScopeBarProps {
  dimension: ScopeDimension;
  selectedIds: string[];
  onDimensionChange: (d: ScopeDimension) => void;
  onSelectedIdsChange: (ids: string[]) => void;
  /** Optional extra UI on the right (e.g. action buttons). */
  rightSlot?: React.ReactNode;
}

const DIMENSIONS: Array<{ id: ScopeDimension; label: string; icon: React.ComponentType<{ size?: number; className?: string }> }> = [
  { id: "client", label: "Client", icon: Building2 },
  { id: "industry", label: "Industry", icon: Briefcase },
  { id: "geo", label: "Geography", icon: Globe2 },
];

/**
 * Renders the global-view scope selector: pick a dimension (Client / Industry / Geography),
 * then pick one or more groups inside that dimension as chips.
 *
 * The list of available groups is fetched from `/api/v1/global/groups`. Empty selection
 * means "all groups in this dimension" — i.e. truly global.
 */
export function ScopeBar({ dimension, selectedIds, onDimensionChange, onSelectedIdsChange, rightSlot }: ScopeBarProps) {
  const { data: groups, isLoading } = useQuery<GlobalGroupsResponse>({
    queryKey: ["/api/v1/global/groups"],
  });

  const available = useMemo<ScopeGroup[]>(() => {
    if (!groups) return [];
    return groups[dimension] ?? [];
  }, [groups, dimension]);

  const isAllSelected = selectedIds.length === 0;

  function toggle(id: string) {
    if (selectedIds.includes(id)) {
      onSelectedIdsChange(selectedIds.filter((x) => x !== id));
    } else {
      onSelectedIdsChange([...selectedIds, id]);
    }
  }

  return (
    <Card className="p-4 mb-4" data-testid="card-scope-bar">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
          <Network size={14} className="text-primary" />
          Global scope
        </div>

        {/* Dimension picker */}
        <div className="inline-flex rounded-md border bg-background p-0.5" role="tablist" data-testid="group-dimension">
          {DIMENSIONS.map(({ id, label, icon: Icon }) => {
            const active = dimension === id;
            return (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => {
                  onDimensionChange(id);
                  onSelectedIdsChange([]); // reset chips on dimension change
                }}
                data-testid={`tab-dimension-${id}`}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-sm transition-colors ${
                  active
                    ? "bg-primary text-primary-foreground shadow-sm"
                    : "text-muted-foreground hover:bg-muted/60"
                }`}
              >
                <Icon size={12} />
                {label}
              </button>
            );
          })}
        </div>

        <span className="text-[11px] text-muted-foreground">
          {isAllSelected
            ? `All ${available.length} ${dimension === "geo" ? "geographies" : dimension === "industry" ? "industries" : "clients"}`
            : `${selectedIds.length} selected`}
        </span>

        <div className="flex-1 min-w-[1rem]" />
        {rightSlot}
      </div>

      {/* Chip filter */}
      <div className="mt-3 flex flex-wrap gap-1.5" data-testid="group-scope-chips">
        {isLoading && <span className="text-xs text-muted-foreground">Loading scope groups…</span>}
        {!isLoading && available.length === 0 && (
          <span className="text-xs text-muted-foreground">No groups available for this dimension.</span>
        )}
        {!isLoading && available.map((g) => {
          const selected = selectedIds.includes(g.id);
          return (
            <button
              key={g.id}
              type="button"
              onClick={() => toggle(g.id)}
              data-testid={`chip-scope-${g.id}`}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs transition-colors ${
                selected
                  ? "bg-primary/15 border-primary/40 text-primary"
                  : "bg-background border-border text-muted-foreground hover:bg-muted/60"
              }`}
              aria-pressed={selected}
            >
              <span>{g.label}</span>
              <Badge variant="secondary" className="h-4 px-1.5 text-[10px] font-mono">
                {g.tenantIds.length}
              </Badge>
            </button>
          );
        })}
        {!isLoading && selectedIds.length > 0 && (
          <Button
            variant="ghost" size="sm"
            className="h-6 px-2 text-[11px]"
            onClick={() => onSelectedIdsChange([])}
            data-testid="button-scope-clear"
          >
            Clear
          </Button>
        )}
      </div>
    </Card>
  );
}
