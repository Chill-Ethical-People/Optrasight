import { useState, type FormEvent, type ReactNode } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Logo } from "@/components/Logo";
import { useToast } from "@/hooks/use-toast";
import { ArrowRight, CheckCircle2, RadioTower, ScanSearch, ShieldCheck } from "lucide-react";

/** OptraSight login — signal-plane brand entry and tenant sign-in. */
export default function Login() {
  const { login, loading } = useAuth();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [email, setEmail] = useState("analyst@acmebank.com");
  const [password, setPassword] = useState("demo1234");
  const [submitting, setSubmitting] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(email, password);
      navigate("/");
    } catch (err: any) {
      toast({ variant: "destructive", title: "Sign-in failed", description: err.message });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="os-identity-shell min-h-screen flex items-center justify-center px-4 sm:px-8 py-8">
      <div className="relative z-10 w-full max-w-[1180px] grid grid-cols-1 xl:grid-cols-[1.2fr_0.8fr] gap-6 xl:gap-8">

        {/* Hero panel */}
        <div className="os-orbit-card rounded-[22px] p-7 sm:p-10 xl:p-12 flex flex-col justify-between min-h-[430px] xl:min-h-[620px]">
          <div className="relative z-10 max-w-2xl">
            <div className="os-brand-kicker mb-7">Omnidirectional threat observatory</div>

            <div className="flex items-center gap-4 mb-8">
              <div className="rounded-2xl border border-primary/20 bg-background/70 p-3 shadow-sm">
                <Logo size={58} className="text-primary shrink-0" />
              </div>
              <div className="flex flex-col leading-none">
                <span className="os-wordmark text-[38px] sm:text-[44px]"><span className="opt">Optra</span><span className="sight">Sight</span></span>
                <span className="os-tc-sub mt-2" style={{ letterSpacing: "0.32em" }}>全 向 預 警 台</span>
              </div>
            </div>

            <h1 className="os-display max-w-[760px]">
              See the threat before it becomes work.
            </h1>
            <p className="text-[15px] text-muted-foreground leading-[1.7] mt-6 max-w-[580px]">
              A proprietary blue-team command surface for MSSPs: external exposure,
              OSINT signal, actor behavior, detections, and response exercises in one
              traceable observatory.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-9 max-w-[650px]">
              <Proof icon={<RadioTower size={16} />} label="Signal intake" value="OSINT and feeds" />
              <Proof icon={<ScanSearch size={16} />} label="Exposure view" value="Assets to TTPs" />
              <Proof icon={<ShieldCheck size={16} />} label="Response path" value="Cases to rules" />
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
              <BrandLine text="No mock confidence in production paths" />
              <BrandLine text="Evidence linked from finding to detection" />
              <BrandLine text="Built for tenant-aware MSSP operations" />
            </div>
          </div>
        </div>

        {/* Form panel */}
        <div className="os-card p-7 sm:p-9 flex flex-col justify-center min-h-[420px] xl:min-h-[620px]">
          <div className="mb-7">
            <h2 className="os-page-title">Sign in</h2>
            <p className="text-sm text-muted-foreground leading-[1.55] mt-1.5">
              Enter the observatory with a demo tenant or your client credentials.
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-[11px] font-medium uppercase text-muted-foreground" style={{ letterSpacing: "0.12em" }} htmlFor="email">Email</label>
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
              <label className="text-[11px] font-medium uppercase text-muted-foreground" style={{ letterSpacing: "0.12em" }} htmlFor="password">Password</label>
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
            <Button
              type="submit"
              className="w-full h-11 mt-2"
              disabled={submitting || loading}
              data-testid="button-login"
            >
              {submitting ? "Signing in…" : <><span>Enter observatory</span><ArrowRight size={15} /></>}
            </Button>
          </form>

          <div className="mt-8 pt-5 border-t border-border/60 space-y-2 text-[11px] text-muted-foreground leading-[1.6]">
            <div className="os-eyebrow text-muted-foreground mb-1">Demo tenants</div>
            <div>
              <span className="os-mono">analyst@acmebank.com</span> · <span className="os-mono">demo1234</span>
            </div>
            <div>
              <span className="os-mono">ciso@globex.example</span> · <span className="os-mono">demo1234</span>
            </div>
            <div>
              MSSP admin · <span className="os-mono">admin@brandguard.local</span> · <span className="os-mono">admin1234</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Proof({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="os-brand-proof">
      <div className="flex items-center gap-2 text-primary">
        {icon}
        <span className="text-[10px] uppercase font-semibold" style={{ letterSpacing: "0.1em" }}>{label}</span>
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
