import { useEffect, useState, type ReactNode } from "react";
import { Link, useLocation } from "wouter";
import {
  LayoutDashboard, LogOut, Building2,
  Sun, Moon, PanelLeftClose, PanelLeftOpen, ChevronDown, Menu,
  ListChecks, Fingerprint, BrainCircuit, RadioTower, Users,
} from "lucide-react";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { AiJobsTray } from "@/components/AiJobsTray";
import { GlobalCommandPalette } from "@/components/GlobalCommandPalette";
import OsintChatbot from "@/components/OsintChatbot";
import { useAuth } from "@/lib/auth";
import { useUiState, type SidebarMode } from "@/lib/uiState";
import { BATCH_ONE_RELEASE } from "@/lib/release";
import { Logo } from "./Logo";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/** Legacy sentinel retained only so old global-mode guards stay compile-time inert in BatchOne. */
export const GLOBAL_TENANT_ID = "__global__";

// Grouped navigation — collapsible sections keep the rail scannable.
// Group ids are stable so collapse-state survives re-renders.
type NavItem = { href: string; label: string; icon: typeof LayoutDashboard; adminOnly?: boolean };
type NavGroup = { id: string; label: string; items: NavItem[] };

const navGroups: NavGroup[] = [
  {
    id: "intel",
    label: "Threat Intel",
    items: [
      { href: "/osint", label: "Intel Inbox", icon: RadioTower },
      { href: "/threat-actors", label: "Actor Observatory", icon: Fingerprint },
    ],
  },
  {
    id: "admin",
    label: "Operations",
    items: [
      { href: "/ai-setup", label: "AI Setup", icon: BrainCircuit },
      { href: "/operations-audit", label: "Job Control", icon: ListChecks },
      { href: "/platform-users", label: "Platform Users", icon: Users, adminOnly: true },
    ],
  },
];

function TenantSwitcher() {
  const { user } = useAuth();

  if (!user) return null;
  return (
    <div
      className="flex items-center gap-2 px-3 h-9 rounded-md border bg-muted/30 text-sm"
      data-testid="badge-release-scope"
    >
      <Building2 size={14} className="text-muted-foreground" />
      <span className="font-medium truncate max-w-[180px]">
        {user.tenant.name}
      </span>
      <Badge variant="secondary" className="text-[10px] uppercase tracking-wide">
        Batch 1
      </Badge>
    </div>
  );
}

/** Theme toggle — single button that flips light ↔ dark. */
function ThemeToggle() {
  const { theme, toggleTheme } = useUiState();
  const next = theme === "dark" ? "light" : "dark";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost" size="icon"
          onClick={toggleTheme}
          className="h-9 w-9"
          data-testid="button-theme-toggle"
          aria-label={`Switch to ${next} mode`}
        >
          {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>Switch to {next} mode</TooltipContent>
    </Tooltip>
  );
}

/** Sidebar collapse control — single click flips expanded ↔ collapsed. */
function SidebarToggle() {
  const { sidebarMode, cycleSidebar } = useUiState();
  const nextLabel: Record<SidebarMode, string> = {
    expanded: "Collapse sidebar",
    collapsed: "Expand sidebar",
  };
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost" size="icon"
          onClick={cycleSidebar}
          className="h-9 w-9"
          data-testid="button-sidebar-toggle"
          aria-label={nextLabel[sidebarMode]}
        >
          {sidebarMode === "expanded"
            ? <PanelLeftClose size={16} />
            : <PanelLeftOpen size={16} />}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{nextLabel[sidebarMode]}</TooltipContent>
    </Tooltip>
  );
}

/** Single nav row — adapts to expanded vs. icon-only rail. */
function NavRow({
  href, label, Icon, active, collapsed,
}: {
  href: string; label: string;
  Icon: typeof LayoutDashboard;
  active: boolean; collapsed: boolean;
}) {
  const testId = `link-${label.toLowerCase().replace(/\s/g, "-")}`;
  // Preview spec: active = brand-soft fill + brand text + brand icon.
  // Inactive rows use muted-foreground so hover/active contrast is unmistakable.
  const className = [
    "os-nav-link flex items-center rounded-md text-sm",
    collapsed
      ? "justify-center h-10 w-10 mx-auto"
      : "gap-3 px-3 py-2",
    active
      ? "bg-[hsl(var(--brand-soft))]/70 text-[hsl(var(--brand))] font-semibold"
      : "text-muted-foreground hover:bg-muted/55 hover:text-foreground",
  ].join(" ");

  // In collapsed mode wrap with a tooltip so analysts can confirm the destination
  // without expanding the rail.
  const link = (
    <Link
      href={href}
      data-testid={testId}
      className={className}
      data-active={active}
      aria-label={label}
      aria-current={active ? "page" : undefined}
      title={collapsed ? label : undefined}
    >
      <Icon size={collapsed ? 18 : 16} className="os-nav-icon" strokeWidth={1.8} />
      {!collapsed && <span className="truncate">{label}</span>}
    </Link>
  );
  if (!collapsed) return link;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  );
}

/** Collapsible group of nav rows. Header is hidden in icon-rail mode — we still
 *  render the items but separate groups with a thin divider so the grouping is
 *  visible even when labels are gone. */
function NavGroupSection({
  group, location, collapsed,
}: {
  group: NavGroup; location: string; collapsed: boolean;
}) {
  const [open, setOpen] = useState(true);
  const isActiveGroup = group.items.some(
    (i) => location === i.href || (i.href !== "/" && location.startsWith(i.href)),
  );
  // Force-expanded if a child is active so users don't lose context after navigation.
  const showItems = collapsed || open || isActiveGroup;

  if (collapsed) {
    return (
      <div className="space-y-1">
        <div className="h-px bg-sidebar-border/60 mx-2 first:hidden" />
        {group.items.map(({ href, label, icon: Icon }) => {
          const active = location === href || (href !== "/" && location.startsWith(href));
          return (
            <NavRow key={href} href={href} label={label} Icon={Icon} active={active} collapsed />
          );
        })}
      </div>
    );
  }

  return (
    <div className="mb-2 last:mb-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-2 px-3 pt-3 pb-1.5 text-[11px] font-medium uppercase text-muted-foreground/75 hover:text-foreground transition-colors"
        style={{ letterSpacing: "0.14em" }}
        data-testid={`button-nav-group-${group.id}`}
        aria-expanded={showItems}
      >
        <span>{group.label}</span>
        <ChevronDown
          size={12}
          className={`transition-transform ${showItems ? "" : "-rotate-90"}`}
        />
      </button>
      {showItems && (
        <div className="space-y-0.5">
          {group.items.map(({ href, label, icon: Icon }) => {
            const active = location === href || (href !== "/" && location.startsWith(href));
            return (
              <NavRow key={href} href={href} label={label} Icon={Icon} active={active} collapsed={false} />
            );
          })}
        </div>
      )}
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const [location] = useLocation();
  const { sidebarMode } = useUiState();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const collapsed = sidebarMode === "collapsed";
  const railWidth = collapsed ? "w-[72px]" : "w-[244px]";
  const reviewOnly = user?.access_mode === "guest" || user?.role === "reviewer";
  const visibleNavGroups = navGroups.map((group) => ({
    ...group,
    items: group.items.filter((item) => {
      if (item.adminOnly && user?.role !== "admin") return false;
      if (reviewOnly && !["/osint", "/threat-actors"].includes(item.href)) return false;
      return true;
    }),
  })).filter((group) => group.items.length > 0);

  // Auto-close the mobile drawer on route change so users don't have to dismiss it manually.
  useEffect(() => { setMobileNavOpen(false); }, [location]);

  return (
    <div className="os-app-shell flex min-h-screen w-full bg-background text-foreground">
      <aside
        className={`os-sidebar hidden md:flex ${railWidth} flex-col border-r border-sidebar-border bg-sidebar/95 text-sidebar-foreground transition-[width] duration-200 relative`}
        data-testid={`sidebar-${sidebarMode}`}
      >
        {/* Brand lockup — aperture mark + two-tone wordmark + concise English subline. */}
        <div className={`os-brand-plate flex items-center border-b border-sidebar-border ${collapsed ? "justify-center py-5" : "gap-3 px-5 py-5"}`}>
          <Logo className="text-primary shrink-0" size={collapsed ? 28 : 32} />
          {!collapsed && (
            <div className="flex flex-col leading-tight min-w-0">
              <span className="os-wordmark text-[17px]"><span className="opt">Optra</span><span className="sight">Sight</span></span>
              <span className="os-brand-sub">Evidence-led operations</span>
            </div>
          )}
        </div>
        {!collapsed && (
          <div className="os-brand-module">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-[10px] font-semibold uppercase text-primary" style={{ letterSpacing: "0.12em" }}>
                  Signal plane
                </div>
                <div className="mt-1 text-[11px] leading-snug text-muted-foreground">
                  Evidence-led threat operations
                </div>
              </div>
              <div className="h-7 w-7 shrink-0 rounded-md border border-primary/15 bg-background/70 flex items-center justify-center">
                <RadioTower size={15} className="text-primary" strokeWidth={1.8} />
              </div>
            </div>
            <div className="os-signal-rule mt-3" />
          </div>
        )}
        {/* Nav */}
        <nav className={`flex-1 overflow-y-auto ${collapsed ? "px-1 py-3 space-y-1" : "px-2 py-3"}`}>
          {visibleNavGroups.map((group) => (
            <NavGroupSection
              key={group.id}
              group={group}
              location={location}
              collapsed={collapsed}
            />
          ))}
        </nav>
        {/* User + sign-out */}
        <div className={`border-t border-sidebar-border ${collapsed ? "p-2" : "p-3"}`}>
          {user && !collapsed && (
            <div className="flex items-center gap-2.5 mb-2 px-1.5">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="text-xs bg-primary/15 text-primary">
                  {user.email.slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <div className="flex flex-col min-w-0">
                <span className="text-xs font-medium truncate" data-testid="text-user-email">{user.email}</span>
                <span className="text-[10px] text-muted-foreground truncate">
                  {reviewOnly ? "Read-only reviewer" : user.role === "admin" ? "Platform admin" : user.tenant?.name}
                </span>
              </div>
            </div>
          )}
          {collapsed ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost" size="icon"
                  className="h-10 w-10 mx-auto flex"
                  onClick={logout}
                  data-testid="button-logout"
                  aria-label="Sign out"
                >
                  <LogOut size={16} />
                </Button>
              </TooltipTrigger>
              <TooltipContent side="right">Sign out</TooltipContent>
            </Tooltip>
          ) : (
            <Button
              variant="ghost" size="sm"
              className="w-full justify-start text-muted-foreground"
              onClick={logout}
              data-testid="button-logout"
            >
              <LogOut size={14} className="mr-2" />
              Sign out
            </Button>
          )}
        </div>
      </aside>

      <main className="flex-1 min-w-0 flex flex-col overflow-x-hidden w-full max-w-full">
        {/* Top bar — mobile menu / sidebar toggle on the left, theme + tray + tenant on the right. */}
        <div className="os-topbar flex items-center gap-2 md:gap-3 border-b backdrop-blur-xl px-3 md:px-6 h-14 sticky top-0 z-20">
          {/* Mobile hamburger — opens the nav drawer. Hidden on md+. */}
          <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
            <Button
              variant="ghost" size="icon"
              className="md:hidden h-9 w-9"
              onClick={() => setMobileNavOpen(true)}
              data-testid="button-mobile-nav-open"
              aria-label="Open navigation"
            >
              <Menu size={18} />
            </Button>
            <SheetContent side="left" className="w-[280px] p-0 bg-sidebar text-sidebar-foreground">
              {/* NEVER add `relative` to SheetContent — wrap children in a relative container. */}
              <div className="relative min-h-full flex flex-col">
                <SheetHeader className="os-brand-plate px-5 py-4 border-b border-sidebar-border text-left">
                  <SheetTitle className="flex items-center gap-3">
                    <Logo className="text-primary shrink-0" size={28} />
                    <div className="flex flex-col leading-tight text-left min-w-0">
                      <span className="os-wordmark text-[16px]"><span className="opt">Optra</span><span className="sight">Sight</span></span>
                      <span className="os-brand-sub">Evidence-led operations</span>
                    </div>
                  </SheetTitle>
                </SheetHeader>
                <nav className="flex-1 overflow-y-auto px-2 py-3">
                  {visibleNavGroups.map((group) => (
                    <NavGroupSection
                      key={group.id}
                      group={group}
                      location={location}
                      collapsed={false}
                    />
                  ))}
                </nav>
                {user && (
                  <div className="border-t border-sidebar-border p-3">
                    <div className="flex items-center gap-2.5 mb-2 px-1.5">
                      <Avatar className="h-8 w-8">
                        <AvatarFallback className="text-xs bg-primary/15 text-primary">
                          {user.email.slice(0, 2).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div className="flex flex-col min-w-0">
                        <span className="text-xs font-medium truncate">{user.email}</span>
                        <span className="text-[10px] text-muted-foreground truncate">
                          {reviewOnly ? "Read-only reviewer" : user.role === "admin" ? "Platform admin" : user.tenant?.name}
                        </span>
                      </div>
                    </div>
                    <Button
                      variant="ghost" size="sm"
                      className="w-full justify-start text-muted-foreground"
                      onClick={logout}
                      data-testid="button-logout-mobile"
                    >
                      <LogOut size={14} className="mr-2" />
                      Sign out
                    </Button>
                  </div>
                )}
              </div>
            </SheetContent>
          </Sheet>
          {/* Desktop sidebar collapse toggle. */}
          <div className="hidden md:block"><SidebarToggle /></div>
          <div className="flex items-center gap-2 md:hidden">
            <Logo className="text-primary" size={20} />
            <span className="os-wordmark text-[15px]"><span className="opt">Optra</span><span className="sight">Sight</span></span>
          </div>
          <div className="flex-1 min-w-3" />
          {/* Utility toolbar — fixed-height controls with enough breathing room for shortcut text. */}
          <div className="os-topbar-actions os-util-pill" role="toolbar" aria-label="Platform utilities">
            <GlobalCommandPalette />
            <ThemeToggle />
            <AiJobsTray />
          </div>
          {!BATCH_ONE_RELEASE && (
            <div className="hidden sm:block shrink-0"><TenantSwitcher /></div>
          )}
        </div>
        <div className="flex-1 min-w-0">{children}</div>
        <OsintChatbot />
      </main>
    </div>
  );
}
