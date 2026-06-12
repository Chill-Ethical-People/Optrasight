import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  CheckCircle2, KeyRound, Lock, RotateCcw, Search, ShieldCheck,
  UserCog, UserMinus, UserPlus, Users,
} from "lucide-react";
import { AppShell } from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { apiRequest, getQueryFn, queryClient } from "@/lib/queryClient";
import {
  emptyPlatformUserForm,
  formFromPlatformUser,
  isComplexPassword,
  PLATFORM_ROLE_LABELS,
  platformUserErrorMessage,
  type PlatformUser,
  type PlatformUserForm,
  type PlatformUserRole,
} from "@/lib/platformUsers";

const FILTER_ALL = "__all__";

const ROLE_HELP: Record<PlatformUserRole, string> = {
  admin: "Manage platform users, AI setup, source operations, and BatchOne release controls.",
  threat_intel_expert: "Review intel, run analysis tasking, maintain sources, and operate analyst workflows.",
  detection_engineer: "Reserved for detection engineering workflows where enabled by the release surface.",
  reviewer: "Read-only review access for executive or UAT validation without write controls.",
};

const ROLE_TONE: Record<PlatformUserRole, string> = {
  admin: "border-primary/35 bg-primary/10 text-primary dark:text-indigo-200",
  threat_intel_expert: "border-cyan-400/35 bg-cyan-400/10 text-cyan-700 dark:text-cyan-200",
  detection_engineer: "border-violet-400/35 bg-violet-400/10 text-violet-700 dark:text-violet-200",
  reviewer: "border-emerald-400/35 bg-emerald-400/10 text-emerald-700 dark:text-emerald-200",
};

function roleLabel(role: string): string {
  return PLATFORM_ROLE_LABELS[role as PlatformUserRole] ?? role;
}

function roleTone(role: string): string {
  return ROLE_TONE[role as PlatformUserRole] ?? "border-slate-400/35 bg-slate-400/10 text-slate-700 dark:text-slate-200";
}

function activeUser(row: PlatformUser): boolean {
  return (row.status ?? "active") === "active";
}

function lastLoginLabel(value?: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Never";
  return date.toLocaleString();
}

function statsFor(users: PlatformUser[]) {
  return {
    total: users.length,
    active: users.filter(activeUser).length,
    admins: users.filter((row) => row.role === "admin").length,
  };
}

function emptyMessage(hasFilters: boolean): string {
  return hasFilters ? "No platform users match the current filters." : "No platform users have been created yet.";
}

export default function PlatformUsers() {
  const { user } = useAuth();
  const { toast } = useToast();
  const isAdmin = user?.role === "admin";
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<PlatformUser | null>(null);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState(FILTER_ALL);
  const [statusFilter, setStatusFilter] = useState(FILTER_ALL);
  const [selectedUserIds, setSelectedUserIds] = useState<Set<string>>(() => new Set());
  const [form, setForm] = useState<PlatformUserForm>(() => emptyPlatformUserForm());

  const { data: usersData, isLoading } = useQuery<{ users: PlatformUser[] }>({
    queryKey: ["/api/v1/admin/platform-users"],
    queryFn: getQueryFn({ on401: "throw" }),
    enabled: isAdmin,
  });

  const users = usersData?.users ?? [];
  const stats = useMemo(() => statsFor(users), [users]);
  const roleSummary = useMemo(() => {
    return (Object.keys(PLATFORM_ROLE_LABELS) as PlatformUserRole[]).map((role) => ({
      id: role,
      label: PLATFORM_ROLE_LABELS[role],
      help: ROLE_HELP[role],
      tone: ROLE_TONE[role],
      count: users.filter((row) => row.role === role).length,
    }));
  }, [users]);
  const filteredUsers = useMemo(() => {
    const q = search.trim().toLowerCase();
    return users.filter((row) => {
      const haystack = [
        row.email,
        row.displayName ?? "",
        row.role,
      ].join(" ").toLowerCase();
      if (q && !haystack.includes(q)) return false;
      if (roleFilter !== FILTER_ALL && row.role !== roleFilter) return false;
      if (statusFilter !== FILTER_ALL && (row.status ?? "active") !== statusFilter) return false;
      return true;
    });
  }, [roleFilter, search, statusFilter, users]);

  const hasFilters = Boolean(search.trim()) || roleFilter !== FILTER_ALL || statusFilter !== FILTER_ALL;
  const selectedIds = Array.from(selectedUserIds).filter((id) => users.some((row) => row.id === id && row.id !== user?.id));
  const selectableFilteredIds = filteredUsers.filter((row) => row.id !== user?.id).map((row) => row.id);
  const allVisibleSelected = selectableFilteredIds.length > 0 && selectableFilteredIds.every((id) => selectedUserIds.has(id));

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ["/api/v1/admin/platform-users"] });
  }

  function startNew() {
    setEditing(null);
    setForm(emptyPlatformUserForm());
    setOpen(true);
  }

  function startEdit(row: PlatformUser) {
    setEditing(row);
    setForm(formFromPlatformUser(row));
    setOpen(true);
  }

  function toggleSelectedUser(uid: string, checked: boolean) {
    setSelectedUserIds((current) => {
      const next = new Set(current);
      if (checked) next.add(uid);
      else next.delete(uid);
      return next;
    });
  }

  function toggleAllVisible(checked: boolean) {
    setSelectedUserIds((current) => {
      const next = new Set(current);
      for (const uid of selectableFilteredIds) {
        if (checked) next.add(uid);
        else next.delete(uid);
      }
      return next;
    });
  }

  const saveUser = useMutation({
    mutationFn: async () => {
      const payload: Record<string, unknown> = {
        email: form.email.trim(),
        role: form.role,
        displayName: form.displayName.trim() || null,
        status: form.status,
      };
      if (!editing || form.password.trim()) payload.password = form.password;
      if (editing) return apiRequest("PUT", `/api/v1/admin/platform-users/${editing.id}`, payload);
      return apiRequest("POST", "/api/v1/admin/platform-users", payload);
    },
    onSuccess: () => {
      toast({ title: editing ? "Platform user updated" : "Platform user created" });
      setOpen(false);
      setEditing(null);
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "User update failed", description: platformUserErrorMessage(err) }),
  });

  const disableUser = useMutation({
    mutationFn: (uid: string) => apiRequest("POST", `/api/v1/admin/platform-users/${uid}/disable`, {}),
    onSuccess: () => {
      toast({ title: "Platform login disabled", description: "The account remains visible for audit continuity." });
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "Disable failed", description: platformUserErrorMessage(err) }),
  });

  const resetMfa = useMutation({
    mutationFn: (uid: string) => apiRequest("POST", `/api/v1/admin/platform-users/${uid}/reset-mfa`, {}),
    onSuccess: () => {
      toast({ title: "MFA reset", description: "The user will enroll a new authenticator on next login." });
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "MFA reset failed", description: platformUserErrorMessage(err) }),
  });

  const bulkManage = useMutation({
    mutationFn: async (action: "disable" | "delete") => {
      if (action === "delete") {
        const ok = window.confirm(`Delete ${selectedIds.length} selected platform account${selectedIds.length === 1 ? "" : "s"}? This removes the account records and revokes active sessions.`);
        if (!ok) return null;
      }
      const response = await apiRequest("POST", "/api/v1/admin/platform-users/bulk", { action, userIds: selectedIds });
      return response.json() as Promise<{ action: string; changed: Array<{ id: string }>; missing: string[] }>;
    },
    onSuccess: (result) => {
      if (!result) return;
      toast({
        title: result.action === "delete" ? "Selected users deleted" : "Selected users disabled",
        description: `${result.changed.length} account${result.changed.length === 1 ? "" : "s"} updated.`,
      });
      setSelectedUserIds(new Set());
      invalidate();
    },
    onError: (err) => toast({ variant: "destructive", title: "Bulk update failed", description: platformUserErrorMessage(err) }),
  });

  const canSave = form.email.trim()
    && form.role
    && (editing ? !form.password || isComplexPassword(form.password) : isComplexPassword(form.password));

  return (
    <AppShell>
      <div className="px-6 md:px-10 py-8 max-w-7xl">
        <PageHeader
          title="Platform Users"
          description="Manage BatchOne platform accounts, temporary passwords, MFA enrollment, and least-privileged access."
          actions={isAdmin ? (
            <Button onClick={startNew} data-testid="button-new-platform-user">
              <UserPlus size={14} className="mr-1.5" /> New platform user
            </Button>
          ) : null}
        />

        {!isAdmin ? (
          <Card className="os-card p-10 text-center">
            <Lock className="mx-auto mb-3 text-muted-foreground" size={28} />
            <div className="text-sm font-semibold">Admin access required</div>
            <p className="mt-1 text-xs text-muted-foreground">Platform user management is reserved for platform administrators.</p>
          </Card>
        ) : (
          <div className="space-y-4">
            <Card className="os-card overflow-hidden border-primary/25 bg-card/95 shadow-[0_18px_45px_rgba(15,23,42,0.06)]">
              <div className="grid gap-4 border-b border-primary/10 p-4 lg:grid-cols-[1.1fr_0.9fr]">
                <div className="flex min-w-0 items-start gap-3">
                  <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-cyan-400/35 bg-cyan-400/10 shadow-[inset_3px_0_0_rgba(34,211,238,0.65)]">
                    <UserCog size={17} className="text-cyan-600 dark:text-cyan-200" />
                  </div>
                  <div className="min-w-0">
                    <div className="os-eyebrow">Internal access control</div>
                    <div className="mt-1 text-base font-semibold text-foreground">Platform identity roster</div>
                    <p className="mt-1 max-w-2xl text-xs leading-5 text-slate-600 dark:text-slate-300">
                      These accounts operate the BatchOne release surface. Review access is read-only; analyst and admin access should stay scoped to the minimum required workflow.
                    </p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Badge variant="outline" className="gap-1 border-primary/25 bg-primary/5 text-[10px] text-primary dark:text-indigo-200"><Users size={11} /> {stats.total} users</Badge>
                      <Badge variant="outline" className="gap-1 border-emerald-400/35 bg-emerald-400/10 text-[10px] text-emerald-700 dark:text-emerald-200"><CheckCircle2 size={11} /> {stats.active} active</Badge>
                      <Badge variant="outline" className="gap-1 border-cyan-400/35 bg-cyan-400/10 text-[10px] text-cyan-700 dark:text-cyan-200"><ShieldCheck size={11} /> {stats.admins} admins</Badge>
                    </div>
                  </div>
                </div>
                <div className="rounded-md border border-border/80 bg-muted/25 p-3 shadow-[inset_3px_0_0_rgba(79,70,229,0.45)] dark:bg-slate-950/35">
                  <div className="text-[11px] font-semibold uppercase text-slate-700 dark:text-slate-200">BatchOne access boundary</div>
                  <p className="mt-1 text-xs leading-5 text-slate-600 dark:text-slate-300">
                    BatchOne is a single-tenant analyst workstation. This page manages users and MFA only; tenant switching and tenant lists are outside the release surface.
                  </p>
                </div>
              </div>
            </Card>

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              {roleSummary.map((role) => (
                <Card key={role.id} className="os-card p-3 transition-colors hover:border-primary/30">
                  <div className="flex items-start justify-between gap-3">
                    <Badge variant="outline" className={`mb-2 text-[10px] font-semibold ${role.tone}`}>{role.label}</Badge>
                    <Badge variant="secondary" className="font-mono text-[10px]">{role.count}</Badge>
                  </div>
                  <p className="text-xs leading-5 text-slate-600 dark:text-slate-300">{role.help}</p>
                </Card>
              ))}
            </div>

            <Card className="os-card p-3">
              <div className="grid gap-3 lg:grid-cols-[1.4fr_0.8fr_0.8fr]">
                <div className="relative">
                  <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search name, email, or role..."
                    className="pl-9"
                    data-testid="input-platform-user-search"
                  />
                </div>
                <Select value={roleFilter} onValueChange={setRoleFilter}>
                  <SelectTrigger data-testid="select-platform-user-role-filter"><SelectValue placeholder="All roles" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>All roles</SelectItem>
                    {(Object.keys(PLATFORM_ROLE_LABELS) as PlatformUserRole[]).map((role) => (
                      <SelectItem key={role} value={role}>{PLATFORM_ROLE_LABELS[role]}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger data-testid="select-platform-user-status-filter"><SelectValue placeholder="All statuses" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={FILTER_ALL}>All statuses</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="disabled">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </Card>

            {isLoading ? (
              <Card className="os-card p-12 text-center text-sm text-muted-foreground">Loading platform users...</Card>
            ) : (
              <Card className="os-card overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 bg-muted/20 px-4 py-3">
                  <div>
                    <div className="os-eyebrow">Platform users</div>
                    <div className="mt-0.5 text-sm font-semibold text-foreground">Internal account registry</div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {selectedIds.length > 0 ? (
                      <>
                        <Badge variant="secondary" className="font-mono text-[10px]">{selectedIds.length} selected</Badge>
                        <Button variant="outline" size="sm" className="h-8" disabled={bulkManage.isPending} onClick={() => bulkManage.mutate("disable")}>
                          <UserMinus size={13} className="mr-1" /> Disable selected
                        </Button>
                        <Button variant="destructive" size="sm" className="h-8" disabled={bulkManage.isPending} onClick={() => bulkManage.mutate("delete")}>
                          Delete selected
                        </Button>
                      </>
                    ) : null}
                    <Badge variant="outline" className="border-primary/25 bg-primary/5 text-[10px] text-primary dark:text-indigo-200">
                      {stats.active} active / {stats.total} total
                    </Badge>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[940px] text-sm">
                    <thead className="border-b bg-muted/35 text-[11px] uppercase text-slate-600 dark:text-slate-300">
                      <tr>
                        <th className="w-10 px-4 py-2.5 text-left font-semibold">
                          <input
                            type="checkbox"
                            className="h-3.5 w-3.5 accent-primary"
                            checked={allVisibleSelected}
                            disabled={selectableFilteredIds.length === 0}
                            onChange={(event) => toggleAllVisible(event.target.checked)}
                            aria-label="Select all visible platform users"
                            data-testid="checkbox-select-all-platform-users"
                          />
                        </th>
                        <th className="px-4 py-2.5 text-left font-semibold">User</th>
                        <th className="px-4 py-2.5 text-left font-semibold">Role</th>
                        <th className="px-4 py-2.5 text-left font-semibold">Status</th>
                        <th className="px-4 py-2.5 text-left font-semibold">Last login</th>
                        <th className="px-4 py-2.5 text-right font-semibold">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredUsers.map((row) => {
                        const isSelf = row.id === user?.id;
                        const isActive = activeUser(row);
                        return (
                          <tr key={row.id} className="border-t border-border/70 transition-colors hover:bg-primary/5" data-testid={`row-platform-user-${row.id}`}>
                            <td className="px-4 py-3">
                              <input
                                type="checkbox"
                                className="h-3.5 w-3.5 accent-primary"
                                checked={selectedUserIds.has(row.id)}
                                disabled={isSelf}
                                onChange={(event) => toggleSelectedUser(row.id, event.target.checked)}
                                aria-label={`Select ${row.email}`}
                                data-testid={`checkbox-platform-user-${row.id}`}
                              />
                            </td>
                            <td className="px-4 py-3">
                              <div className="font-medium text-foreground">{row.displayName || row.email}</div>
                              <div className="os-code-id text-xs">{row.email}</div>
                            </td>
                            <td className="px-4 py-3">
                              <Badge variant="outline" className={`text-[10px] ${roleTone(row.role)}`}>{roleLabel(row.role)}</Badge>
                            </td>
                            <td className="px-4 py-3">
                              <Badge variant={isActive ? "outline" : "secondary"} className={`text-[10px] ${isActive ? "border-emerald-400/35 bg-emerald-400/10 text-emerald-700 dark:text-emerald-200" : "text-muted-foreground"}`}>
                                {isActive ? "Active" : "Disabled"}
                              </Badge>
                              <div className="mt-1 flex flex-wrap gap-1">
                                {row.passwordMustChange ? (
                                  <Badge variant="outline" className="border-amber-400/40 bg-amber-400/10 text-[9px] text-amber-700 dark:text-amber-200">Password setup</Badge>
                                ) : null}
                                <Badge variant="outline" className={row.mfaEnabled ? "border-emerald-400/35 bg-emerald-400/10 text-[9px] text-emerald-700 dark:text-emerald-200" : "border-amber-400/40 bg-amber-400/10 text-[9px] text-amber-700 dark:text-amber-200"}>
                                  MFA {row.mfaEnabled ? "on" : "pending"}
                                </Badge>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-xs text-muted-foreground">{lastLoginLabel(row.lastLoginAt)}</td>
                            <td className="px-4 py-3 text-right">
                              <Button variant="outline" size="sm" className="h-8" onClick={() => startEdit(row)} data-testid={`button-edit-platform-user-${row.id}`}>Edit</Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-8 text-muted-foreground hover:text-foreground"
                                disabled={!isActive || resetMfa.isPending}
                                onClick={() => resetMfa.mutate(row.id)}
                                data-testid={`button-reset-mfa-platform-user-${row.id}`}
                              >
                                <RotateCcw size={13} className="mr-1" /> Reset MFA
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-8 text-muted-foreground hover:text-foreground"
                                disabled={!isActive || isSelf || disableUser.isPending}
                                onClick={() => disableUser.mutate(row.id)}
                                data-testid={`button-disable-platform-user-${row.id}`}
                              >
                                Disable login
                              </Button>
                            </td>
                          </tr>
                        );
                      })}
                      {filteredUsers.length === 0 && (
                        <tr>
                          <td colSpan={6} className="px-4 py-10 text-center text-sm text-muted-foreground">
                            {emptyMessage(hasFilters)}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}
          </div>
        )}
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-base">{editing ? "Edit platform user" : "New platform user"}</DialogTitle>
            <DialogDescription className="text-xs">
              Platform accounts are for internal BatchOne operators. Use the least privileged role that supports the user&apos;s work.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div>
              <Label className="text-xs text-muted-foreground">Display name</Label>
              <Input value={form.displayName} onChange={(event) => setForm({ ...form, displayName: event.target.value })} placeholder="Jane Doe" data-testid="input-platform-user-display-name" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">Email</Label>
              <Input type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} placeholder="jane@cep.com" data-testid="input-platform-user-email" />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label className="text-xs text-muted-foreground">Role</Label>
                <Select value={form.role} onValueChange={(role: PlatformUserRole) => setForm({ ...form, role })}>
                  <SelectTrigger data-testid="select-platform-user-role"><SelectValue placeholder="Select role" /></SelectTrigger>
                  <SelectContent>
                    {(Object.entries(PLATFORM_ROLE_LABELS) as Array<[PlatformUserRole, string]>).map(([role, label]) => (
                      <SelectItem key={role} value={role}>{label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Status</Label>
                <Select value={form.status} onValueChange={(status: "active" | "disabled") => setForm({ ...form, status })}>
                  <SelectTrigger data-testid="select-platform-user-status"><SelectValue placeholder="Select status" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="disabled">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground">{editing ? "Reset password" : "Temporary password"}</Label>
              <Input
                type="password"
                value={form.password}
                onChange={(event) => setForm({ ...form, password: event.target.value })}
                placeholder={editing ? "Leave blank to keep current password" : "12+ chars, upper/lower, number, symbol"}
                data-testid="input-platform-user-password"
              />
              {form.password ? (
                <p className={isComplexPassword(form.password) ? "mt-1 text-xs text-emerald-600 dark:text-emerald-300" : "mt-1 text-xs text-amber-700 dark:text-amber-200"}>
                  {isComplexPassword(form.password)
                    ? "Complex password accepted. The user will still be forced to change it and enroll MFA at next login."
                    : "Use 12+ characters with uppercase, lowercase, number, symbol, and no seeded temporary password."}
                </p>
              ) : (
                <p className="mt-1 text-xs text-muted-foreground">
                  Passwords set here are temporary. The user must change it and set up MFA on next login.
                </p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => saveUser.mutate()} disabled={!canSave || saveUser.isPending} data-testid="button-save-platform-user">
              <KeyRound size={14} className="mr-1.5" /> {editing ? "Save user" : "Create user"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
