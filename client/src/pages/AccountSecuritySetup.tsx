import { useEffect, useMemo, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { CheckCircle2, Copy, KeyRound, Loader2, Lock, ShieldCheck } from "lucide-react";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { apiRequest } from "@/lib/queryClient";

type MfaSetup = {
  enabled: boolean;
  verifiedAt: string | null;
  secret: string;
  otpauthUrl: string;
};

type MeWithMfaSetup = {
  mfaSetup?: MfaSetup | null;
};

async function readJson<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();
  if (!response.ok) throw new Error(text || response.statusText);
  if (!contentType.includes("application/json")) {
    throw new Error(`MFA setup API returned ${contentType || "a non-JSON response"}. Please refresh after restarting the OptraSight server.`);
  }
  return JSON.parse(text) as T;
}

function passwordChecks(value: string, currentPassword: string) {
  return [
    { label: "12+ characters", ok: value.length >= 12 },
    { label: "Uppercase letter", ok: /[A-Z]/.test(value) },
    { label: "Lowercase letter", ok: /[a-z]/.test(value) },
    { label: "Number", ok: /\d/.test(value) },
    { label: "Symbol", ok: /[^A-Za-z0-9]/.test(value) },
    { label: "Not the current password", ok: !!value && value !== currentPassword },
  ];
}

export default function AccountSecuritySetup() {
  const { user, refreshMe, logout } = useAuth();
  const { toast } = useToast();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaSetup, setMfaSetup] = useState<MfaSetup | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [mfaBusy, setMfaBusy] = useState(false);

  const checks = useMemo(() => passwordChecks(newPassword, currentPassword), [currentPassword, newPassword]);
  const passwordValid = checks.every((check) => check.ok) && newPassword === confirmPassword;
  const needsPassword = !!user?.passwordMustChange;
  const needsMfa = !user?.mfaEnabled;

  useEffect(() => {
    if (!needsMfa) return;
    let cancelled = false;
    apiRequest("GET", "/api/v1/me?mfaSetup=1")
      .then((r) => readJson<MeWithMfaSetup>(r))
      .then(async (me) => {
        if (me.mfaSetup) return me.mfaSetup;
        const fallback = await apiRequest("GET", "/api/v1/auth/mfa/setup");
        return readJson<MfaSetup>(fallback);
      })
      .then(async (setup: MfaSetup) => {
        if (cancelled) return;
        setMfaSetup(setup);
        const url = await QRCode.toDataURL(setup.otpauthUrl, {
          margin: 1,
          width: 220,
          color: { dark: "#0f172a", light: "#ffffff" },
        });
        if (!cancelled) setQrDataUrl(url);
      })
      .catch((err) => toast({ variant: "destructive", title: "MFA setup failed", description: String(err.message ?? err) }));
    return () => { cancelled = true; };
  }, [needsMfa, toast]);

  const changePassword = async (event: FormEvent) => {
    event.preventDefault();
    if (!passwordValid) return;
    setPasswordBusy(true);
    try {
      const r = await apiRequest("POST", "/api/v1/auth/change-password", { currentPassword, newPassword });
      if (!r.ok) throw new Error(await r.text());
      await refreshMe();
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      toast({ title: "Password changed", description: "Continue by enrolling MFA." });
    } catch (err: any) {
      toast({ variant: "destructive", title: "Password change failed", description: String(err.message ?? err) });
    } finally {
      setPasswordBusy(false);
    }
  };

  const verifyMfa = async (event: FormEvent) => {
    event.preventDefault();
    setMfaBusy(true);
    try {
      const r = await apiRequest("POST", "/api/v1/auth/mfa/verify", { code: mfaCode });
      if (!r.ok) throw new Error(await r.text());
      const updated = await refreshMe();
      toast({ title: "MFA enabled", description: "Your account security setup is complete." });
      if (!updated?.passwordMustChange && updated?.mfaEnabled) window.location.hash = "#/";
    } catch (err: any) {
      toast({ variant: "destructive", title: "MFA verification failed", description: String(err.message ?? err) });
    } finally {
      setMfaBusy(false);
    }
  };

  const copySeed = () => {
    if (!mfaSetup?.secret) return;
    navigator.clipboard?.writeText(mfaSetup.secret);
    toast({ title: "Seed copied", description: "Paste it into your authenticator if QR scanning is unavailable." });
  };

  return (
    <div className="min-h-screen bg-background px-4 py-8 text-foreground">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-5">
        <div className="flex items-center gap-3">
          <Logo size={34} className="text-primary" />
          <div>
            <div className="os-wordmark text-xl"><span className="opt">Optra</span><span className="sight">Sight</span></div>
            <div className="text-xs text-muted-foreground">Account security setup</div>
          </div>
          <div className="flex-1" />
          <Button variant="outline" size="sm" onClick={logout}>Sign out</Button>
        </div>

        <Card className="os-card p-5">
          <div className="flex items-start gap-3">
            <div className="rounded-md border border-primary/20 bg-primary/10 p-2 text-primary">
              <ShieldCheck size={18} />
            </div>
            <div>
              <div className="text-lg font-semibold">Secure your OptraSight account</div>
              <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
                Seed and reset accounts must use a complex password and MFA before platform functions unlock.
              </p>
            </div>
          </div>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="os-card p-5">
            <div className="mb-4 flex items-center gap-2">
              {needsPassword ? <Lock size={17} className="text-primary" /> : <CheckCircle2 size={17} className="text-emerald-500" />}
              <div className="font-semibold">1. Change temporary password</div>
            </div>
            {needsPassword ? (
              <form onSubmit={changePassword} className="space-y-3">
                <Input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current temporary password" data-testid="input-current-password" />
                <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New complex password" data-testid="input-new-password" />
                <Input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm new password" data-testid="input-confirm-password" />
                <div className="grid grid-cols-2 gap-1.5 text-xs">
                  {checks.map((check) => (
                    <div key={check.label} className={check.ok ? "text-emerald-600 dark:text-emerald-300" : "text-muted-foreground"}>
                      {check.ok ? "OK" : "--"} {check.label}
                    </div>
                  ))}
                  <div className={newPassword && newPassword === confirmPassword ? "text-emerald-600 dark:text-emerald-300" : "text-muted-foreground"}>
                    {newPassword && newPassword === confirmPassword ? "OK" : "--"} Passwords match
                  </div>
                </div>
                <Button type="submit" disabled={!passwordValid || passwordBusy} data-testid="button-change-password">
                  {passwordBusy ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Saving</> : "Save password"}
                </Button>
              </form>
            ) : (
              <div className="rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-700 dark:text-emerald-200">
                Password requirement completed.
              </div>
            )}
          </Card>

          <Card className="os-card p-5">
            <div className="mb-4 flex items-center gap-2">
              {needsMfa ? <KeyRound size={17} className="text-primary" /> : <CheckCircle2 size={17} className="text-emerald-500" />}
              <div className="font-semibold">2. Enroll MFA</div>
            </div>
            {needsMfa ? (
              <form onSubmit={verifyMfa} className="space-y-3">
                <div className="flex flex-col gap-3 sm:flex-row">
                  <div className="flex h-[228px] w-[228px] shrink-0 items-center justify-center rounded-md border bg-white p-2">
                    {qrDataUrl ? <img src={qrDataUrl} alt="Authenticator QR code" className="h-full w-full" /> : <Loader2 className="animate-spin text-slate-500" />}
                  </div>
                  <div className="min-w-0 flex-1 space-y-2 text-sm text-muted-foreground">
                    <p>Scan the QR code with Microsoft Authenticator, Google Authenticator, 1Password, or another TOTP app.</p>
                    <div className="rounded-md border bg-muted/30 p-2">
                      <div className="text-[11px] uppercase text-muted-foreground">Seed key</div>
                      <div className="mt-1 break-all font-mono text-xs text-foreground">{mfaSetup?.secret ?? "Loading..."}</div>
                    </div>
                    <Button type="button" variant="outline" size="sm" onClick={copySeed} disabled={!mfaSetup?.secret}>
                      <Copy size={13} className="mr-1.5" /> Copy seed
                    </Button>
                  </div>
                </div>
                <Input
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="Enter 6-digit code"
                  className="font-mono"
                  data-testid="input-mfa-setup-code"
                />
                <Button type="submit" disabled={mfaCode.length !== 6 || mfaBusy} data-testid="button-verify-mfa">
                  {mfaBusy ? <><Loader2 size={14} className="mr-1.5 animate-spin" />Verifying</> : "Verify MFA"}
                </Button>
              </form>
            ) : (
              <div className="rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-700 dark:text-emerald-200">
                MFA is active for this account.
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
