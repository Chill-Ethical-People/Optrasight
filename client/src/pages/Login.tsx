import { useState, type FormEvent, type ReactNode } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Logo } from "@/components/Logo";
import { useToast } from "@/hooks/use-toast";
import { ArrowRight, CheckCircle2, KeyRound, RadioTower, ShieldCheck, UserRoundCheck } from "lucide-react";

type LoginStep = "credentials" | "mfa";

/** Batch One entry surface: platform admin and read-only reviewer accounts. */
export default function Login() {
  const { login, loading } = useAuth();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [email, setEmail] = useState("admin@cep.com");
  const [password, setPassword] = useState("ChangeMe!2026Admin");
  const [mfaCode, setMfaCode] = useState("");
  const [step, setStep] = useState<LoginStep>("credentials");
  const [submitting, setSubmitting] = useState(false);
  const mfaRequired = step === "mfa";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password, mfaRequired ? mfaCode : undefined);
      navigate("/osint");
    } catch (err: any) {
      if (/MFA code required|mfaRequired/i.test(String(err.message ?? err))) {
        setStep("mfa");
        setMfaCode("");
        toast({ title: "MFA code required", description: "Enter the 6-digit code from your authenticator app." });
      } else {
        if (!mfaRequired) setStep("credentials");
        toast({ variant: "destructive", title: "Sign-in failed", description: err.message });
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="os-identity-shell min-h-screen flex items-center justify-center px-4 sm:px-8 py-8">
      <div className="relative z-10 w-full max-w-[1180px] grid grid-cols-1 xl:grid-cols-[1.15fr_0.85fr] gap-6 xl:gap-8">
        <section className="os-orbit-card rounded-[22px] p-7 sm:p-10 xl:p-12 flex flex-col justify-between min-h-[430px] xl:min-h-[620px]">
          <div className="relative z-10 max-w-2xl">
            <div className="os-brand-kicker mb-7">OptraSight Intel Workstation</div>

            <div className="flex items-center gap-4 mb-8">
              <div className="rounded-2xl border border-primary/20 bg-background/70 p-3 shadow-sm">
                <Logo size={58} className="text-primary shrink-0" />
              </div>
              <div className="flex flex-col leading-none">
                <span className="os-wordmark text-[38px] sm:text-[44px]">
                  <span className="opt">Optra</span><span className="sight">Sight</span>
                </span>
                <span className="mt-2 text-[11px] font-semibold uppercase text-muted-foreground tracking-[0.22em]">
                  Evidence-led threat operations
                </span>
              </div>
            </div>

            <h1 className="os-display max-w-[760px]">
              Turn threat signal into actor intelligence and hunt logic.
            </h1>
            <p className="text-[15px] text-muted-foreground leading-[1.7] mt-6 max-w-[590px]">
              Review current intel, inspect actor dossiers, and preserve source context
              in one traceable Batch One analyst console.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-9 max-w-[650px]">
              <Proof icon={<RadioTower size={16} />} label="Review" value="Intel intake" />
              <Proof icon={<UserRoundCheck size={16} />} label="Correlate" value="Actor dossiers" />
              <Proof icon={<ShieldCheck size={16} />} label="Queue" value="Hunt queries" />
            </div>
          </div>

          <div className="relative z-10 mt-10 grid grid-cols-1 lg:grid-cols-[1fr_0.86fr] gap-4 items-end">
            <div className="os-observatory-map" aria-hidden="true">
              <div className="os-sweep" />
              <div className="absolute left-[50%] top-[50%] h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full bg-signal shadow-[0_0_0_6px_hsl(var(--signal)/0.14)]" />
              <div className="absolute left-[22%] top-[38%] h-2 w-2 rounded-full bg-primary" />
              <div className="absolute right-[24%] top-[30%] h-2 w-2 rounded-full bg-[hsl(var(--sev-high))]" />
              <div className="absolute bottom-[24%] right-[34%] h-2 w-2 rounded-full bg-signal" />
            </div>
            <div className="space-y-3 text-sm">
              <BrandLine text="Strict mode surfaces provider errors" />
              <BrandLine text="Evidence stays linked from source to finding" />
              <BrandLine text="Batch 1 focuses on intel intake, TAP, AI setup, and job control" />
            </div>
          </div>
        </section>

        <section className="os-card p-7 sm:p-9 flex flex-col justify-center min-h-[420px] xl:min-h-[620px]">
          <div className="mb-7">
            <h2 className="os-page-title">Sign in</h2>
            <p className="text-sm text-muted-foreground leading-[1.55] mt-1.5">
              Sign in with an assigned account. Reviewer accounts are read-only;
              platform admin accounts enable source, automation, and configuration workflows.
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <KeyRound size={16} className="text-primary" />
              Account sign-in
            </div>
            {!mfaRequired ? (
              <>
                <div className="space-y-1.5">
                  <label className="text-[11px] font-medium uppercase text-muted-foreground tracking-[0.12em]" htmlFor="email">Email</label>
                  <Input
                    id="email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    data-testid="input-email"
                    className="h-11"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-[11px] font-medium uppercase text-muted-foreground tracking-[0.12em]" htmlFor="password">Password</label>
                  <Input
                    id="password"
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    data-testid="input-password"
                    className="h-11"
                  />
                </div>
              </>
            ) : (
              <div className="space-y-1.5">
                <label className="text-[11px] font-medium uppercase text-muted-foreground tracking-[0.12em]" htmlFor="mfaCode">MFA code</label>
                <Input
                  id="mfaCode"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="Enter 6-digit code"
                  data-testid="input-mfa-code"
                  className="h-11 font-mono"
                />
              </div>
            )}
            <Button
              type="submit"
              variant="outline"
              className="w-full h-11 mt-2 justify-between"
              disabled={loading || submitting || (mfaRequired && mfaCode.length !== 6)}
              data-testid="button-login"
            >
              <span>{submitting ? "Signing in..." : mfaRequired ? "Verify MFA code" : "Sign in"}</span>
              <ArrowRight size={15} />
            </Button>
          </form>

          <div className="mt-8 pt-5 border-t border-border/60 space-y-2 text-[11px] text-muted-foreground leading-[1.6]">
            <div className="os-eyebrow text-muted-foreground mb-1">Local seed credentials</div>
            <div>
              Platform admin account · <span className="os-mono">admin@cep.com</span>
            </div>
            <div>
              Initial password · <span className="os-mono">ChangeMe!2026Admin</span>
            </div>
            <div>
              Read-only reviewer account · <span className="os-mono">reviewer@cep.com</span>
            </div>
            <div>
              Initial password · <span className="os-mono">ChangeMe!2026Review</span>
            </div>
            <div>
              Rotate local seed credentials before any real use.
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function Proof({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="os-brand-proof">
      <div className="flex items-center gap-2 text-primary">
        {icon}
        <span className="text-[10px] uppercase font-semibold tracking-[0.1em]">{label}</span>
      </div>
      <div className="mt-2 text-[13px] font-semibold text-foreground">{value}</div>
    </div>
  );
}

function BrandLine({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-border bg-background/55 px-3 py-2 text-xs text-muted-foreground">
      <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-primary" />
      <span>{text}</span>
    </div>
  );
}
