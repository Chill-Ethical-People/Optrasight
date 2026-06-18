import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import type { AiProviderSummary } from "@shared/schema";

interface ProvidersResp {
  providers: AiProviderSummary[];
  hasUsableProvider?: boolean;
}

export function useAiAvailability() {
  const query = useQuery<ProvidersResp>({
    queryKey: ["/api/v1/ai/providers"],
    queryFn: async () => {
      const r = await apiRequest("GET", "/api/v1/ai/providers");
      return r.json();
    },
  });
  const providers = query.data?.providers ?? [];
  const hasUsableProvider = query.data?.hasUsableProvider ?? providers.some((p) => p.enabled && p.hasKey && p.lastTestOk === true);
  return {
    ...query,
    providers,
    hasUsableProvider,
    disabledReason: hasUsableProvider ? undefined : "Complete AI Setup: enable a provider, save its API key, and pass the live connection test.",
  };
}
