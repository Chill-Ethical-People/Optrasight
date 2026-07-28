import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, Loader2, LockKeyhole, MailCheck, Save, SendHorizonal } from "lucide-react";
import type { SmtpSettingsDTO } from "@shared/schema";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";

type FormState = Omit<SmtpSettingsDTO, "hasPassword" | "configured"> & {
  password: string;
  clearPassword: boolean;
};

const EMPTY_FORM: FormState = {
  enabled: false,
  host: "",
  port: 587,
  secure: false,
  username: "",
  password: "",
  clearPassword: false,
  fromName: "OptraSight Threat Intelligence",
  fromAddress: "",
  replyTo: "",
};

export function EmailDeliverySettingsDialog({
  open,
  onOpenChange,
  settings,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  settings?: SmtpSettingsDTO;
}) {
  const { toast } = useToast();
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const settingsQuery = useQuery<SmtpSettingsDTO>({
    queryKey: ["/api/v1/email-delivery/settings"],
    queryFn: async () => {
      const response = await apiRequest("GET", "/api/v1/email-delivery/settings");
      return response.json();
    },
    enabled: open && !settings,
    staleTime: 30_000,
  });
  const resolvedSettings = settings ?? settingsQuery.data;
  const settingsLoading = open && !resolvedSettings && settingsQuery.isLoading;

  useEffect(() => {
    if (!open) return;
    setTestResult(null);
    setForm(
      resolvedSettings
        ? {
            enabled: resolvedSettings.enabled,
            host: resolvedSettings.host,
            port: resolvedSettings.port,
            secure: resolvedSettings.secure,
            username: resolvedSettings.username,
            password: "",
            clearPassword: false,
            fromName: resolvedSettings.fromName,
            fromAddress: resolvedSettings.fromAddress,
            replyTo: resolvedSettings.replyTo,
          }
        : EMPTY_FORM,
    );
  }, [open, resolvedSettings]);

  const save = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("PUT", "/api/v1/email-delivery/settings", {
        ...form,
        password: form.password || undefined,
      });
      return response.json() as Promise<SmtpSettingsDTO>;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["/api/v1/email-delivery/settings"] });
      toast({
        title: "Email delivery settings saved",
        description: "The SMTP password remains in the private secrets store and is never returned to the browser.",
      });
      onOpenChange(false);
    },
    onError: (error: Error) =>
      toast({ title: "Could not save email settings", description: error.message, variant: "destructive" }),
  });

  const testConnection = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/v1/email-delivery/test", {});
      return response.json() as Promise<{ verified: boolean }>;
    },
    onSuccess: () =>
      setTestResult({
        ok: true,
        message:
          "Authentication verified. This confirms the saved credentials and TLS settings, but does not submit a message through provider delivery controls.",
      }),
    onError: (error: Error) => setTestResult({ ok: false, message: error.message }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <MailCheck size={18} className="text-primary" />
            Email delivery
          </DialogTitle>
          <DialogDescription>
            Configure the workspace SMTP sender. Only platform administrators can view or change these settings.
          </DialogDescription>
        </DialogHeader>

        {settingsLoading ? (
          <div className="flex min-h-40 items-center justify-center rounded-md border bg-muted/10 text-sm text-muted-foreground">
            <Loader2 size={16} className="mr-2 animate-spin" /> Loading email settings...
          </div>
        ) : null}

        <div className={settingsLoading ? "pointer-events-none opacity-45" : "contents"}>
          <div className="flex items-center justify-between gap-5 rounded-md border border-border bg-muted/20 px-4 py-3">
            <div>
              <div className="text-sm font-medium">Enable SMTP delivery</div>
              <p className="mt-1 text-xs text-muted-foreground">
                Approved client briefs can be sent from Client Briefs.
              </p>
            </div>
            <Switch
              checked={form.enabled}
              onCheckedChange={(enabled) => setForm((current) => ({ ...current, enabled }))}
              aria-label="Enable SMTP delivery"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_120px]">
            <div>
              <Label htmlFor="smtp-host">SMTP host</Label>
              <Input
                id="smtp-host"
                className="mt-2"
                value={form.host}
                onChange={(event) => setForm((current) => ({ ...current, host: event.target.value }))}
                placeholder="smtp.example.com"
              />
            </div>
            <div>
              <Label htmlFor="smtp-port">Port</Label>
              <Input
                id="smtp-port"
                className="mt-2"
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(event) => setForm((current) => ({ ...current, port: Number(event.target.value || 587) }))}
              />
            </div>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-md border border-border px-4 py-3">
            <Checkbox
              className="mt-0.5"
              checked={form.secure}
              onCheckedChange={(checked) =>
                setForm((current) => {
                  const secure = checked === true;
                  return {
                    ...current,
                    secure,
                    port: secure && current.port === 587 ? 465 : !secure && current.port === 465 ? 587 : current.port,
                  };
                })
              }
            />
            <span>
              <span className="block text-sm font-medium">Use implicit TLS</span>
              <span className="mt-1 block text-xs text-muted-foreground">
                Enable for port 465. Port 587 uses required STARTTLS when this is off.
              </span>
            </span>
          </label>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label htmlFor="smtp-username">Username</Label>
              <Input
                id="smtp-username"
                className="mt-2"
                autoComplete="off"
                value={form.username}
                onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
              />
            </div>
            <div>
              <Label htmlFor="smtp-password">Password or app password</Label>
              <Input
                id="smtp-password"
                className="mt-2"
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={(event) =>
                  setForm((current) => ({ ...current, password: event.target.value, clearPassword: false }))
                }
                placeholder={resolvedSettings?.hasPassword ? "Saved - leave blank to keep" : "Enter SMTP password"}
              />
            </div>
          </div>

          {resolvedSettings?.hasPassword ? (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
              <Checkbox
                checked={form.clearPassword}
                onCheckedChange={(checked) =>
                  setForm((current) => ({
                    ...current,
                    clearPassword: checked === true,
                    password: checked ? "" : current.password,
                  }))
                }
              />
              Remove the saved SMTP password when these settings are saved
            </label>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label htmlFor="smtp-from-name">Sender name</Label>
              <Input
                id="smtp-from-name"
                className="mt-2"
                value={form.fromName}
                onChange={(event) => setForm((current) => ({ ...current, fromName: event.target.value }))}
              />
            </div>
            <div>
              <Label htmlFor="smtp-from-address">Sender email</Label>
              <Input
                id="smtp-from-address"
                className="mt-2"
                type="email"
                value={form.fromAddress}
                onChange={(event) => setForm((current) => ({ ...current, fromAddress: event.target.value }))}
                placeholder="threat-intel@example.com"
              />
            </div>
          </div>
          <div>
            <Label htmlFor="smtp-reply-to">
              Reply-to email <span className="font-normal text-muted-foreground">(optional)</span>
            </Label>
            <Input
              id="smtp-reply-to"
              className="mt-2"
              type="email"
              value={form.replyTo}
              onChange={(event) => setForm((current) => ({ ...current, replyTo: event.target.value }))}
            />
          </div>

          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/20 px-3 py-2.5 text-[11px] leading-5 text-muted-foreground">
            <LockKeyhole size={14} className="mt-0.5 shrink-0 text-primary" />
            Credentials are stored in the workspace secrets database with restricted file permissions. Password values
            are never included in API responses or audit details.
          </div>

          {testResult ? (
            <div
              className={`flex items-start gap-2 rounded-md border px-3 py-2.5 text-xs leading-5 ${testResult.ok ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-red-200 bg-red-50 text-red-800"}`}
              role="status"
            >
              {testResult.ok ? (
                <CheckCircle2 size={15} className="mt-0.5 shrink-0" />
              ) : (
                <CircleAlert size={15} className="mt-0.5 shrink-0" />
              )}
              <span>{testResult.message}</span>
            </div>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={save.isPending}>
            Cancel
          </Button>
          <Button
            variant="outline"
            onClick={() => testConnection.mutate()}
            disabled={
              settingsLoading ||
              save.isPending ||
              testConnection.isPending ||
              !resolvedSettings?.configured ||
              !resolvedSettings.enabled
            }
            title={
              !resolvedSettings?.configured || !resolvedSettings.enabled
                ? "Save and enable the SMTP settings before testing"
                : "Verify saved SMTP authentication without sending email"
            }
          >
            {testConnection.isPending ? (
              <Loader2 size={14} className="mr-2 animate-spin" />
            ) : (
              <SendHorizonal size={14} className="mr-2" />
            )}
            Test authentication
          </Button>
          <Button
            onClick={() => save.mutate()}
            disabled={settingsLoading || save.isPending || !form.host || !form.fromAddress || !form.fromName}
          >
            {save.isPending ? <Loader2 size={14} className="mr-2 animate-spin" /> : <Save size={14} className="mr-2" />}
            Save settings
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
