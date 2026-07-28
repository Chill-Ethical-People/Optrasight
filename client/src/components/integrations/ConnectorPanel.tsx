import type { ReactNode } from "react";
import * as Collapsible from "@radix-ui/react-collapsible";
import { ChevronDown } from "lucide-react";
import { Card } from "@/components/ui/card";

interface ConnectorPanelProps {
  icon: ReactNode;
  title: string;
  description: string;
  badges?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  iconClassName?: string;
  defaultOpen?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export function ConnectorPanel({
  icon,
  title,
  description,
  badges,
  action,
  children,
  iconClassName = "border-primary/20 bg-primary/10 text-primary",
  defaultOpen = false,
  open,
  onOpenChange,
}: ConnectorPanelProps) {
  return (
    <Collapsible.Root defaultOpen={defaultOpen} open={open} onOpenChange={onOpenChange} asChild>
      <Card className="group/connector overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-4">
          <Collapsible.Trigger asChild>
            <button type="button" className="flex min-w-0 flex-1 items-start gap-3 text-left">
              <span className={`flex size-9 shrink-0 items-center justify-center rounded-md border ${iconClassName}`}>
                {icon}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-foreground">{title}</span>
                  {badges}
                </span>
                <span className="mt-1 block text-xs leading-5 text-muted-foreground">{description}</span>
              </span>
              <ChevronDown
                size={16}
                className="mt-2 shrink-0 text-muted-foreground transition-transform duration-200 group-data-[state=open]/connector:rotate-180"
                aria-hidden="true"
              />
            </button>
          </Collapsible.Trigger>
          {action ? <div className="shrink-0">{action}</div> : null}
        </div>
        <Collapsible.Content className="overflow-hidden border-t data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down">
          {children}
        </Collapsible.Content>
      </Card>
    </Collapsible.Root>
  );
}
