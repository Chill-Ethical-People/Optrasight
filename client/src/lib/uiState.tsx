import {
  createContext, useContext, useEffect, useMemo, useState,
  type ReactNode,
} from "react";

// ---------- Theme ----------
// Two real modes (light / dark). The "system" choice exists only at boot —
// once the user toggles, the explicit choice sticks for the session.
// We do NOT use localStorage (sandboxed iframe rule); state is per-session.
export type Theme = "light" | "dark";

function applyTheme(theme: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (theme === "dark") root.classList.add("dark");
  else root.classList.remove("dark");
  // Hint to UA-styled form controls so date pickers etc. follow the theme too.
  root.style.colorScheme = theme;
}

// ---------- Sidebar ----------
// 'expanded'  — full 240px shell with labels
// 'collapsed' — icon-only 64px rail; tooltips on hover (handled in AppShell)
//
// Two-state model (v2.30.2.3 onwards). The old 'hidden' off-canvas mode
// was removed — users almost never want to hide the rail entirely, and the
// three-state cycle made re-expanding from collapsed take two clicks.
export type SidebarMode = "expanded" | "collapsed";

interface UiStateValue {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (t: Theme) => void;
  sidebarMode: SidebarMode;
  setSidebarMode: (m: SidebarMode) => void;
  cycleSidebar: () => void;
}

const UiStateContext = createContext<UiStateValue | null>(null);

/** Initial theme — system preference; falls back to light. */
function initialTheme(): Theme {
  if (typeof window === "undefined") return "light";
  const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)")?.matches;
  return prefersDark ? "dark" : "light";
}

/** Initial sidebar mode — collapsed below 1280px viewports for laptop / iPad
 *  landscape, expanded on wider screens. The user can override at any time. */
function initialSidebarMode(): SidebarMode {
  if (typeof window === "undefined") return "expanded";
  return window.innerWidth < 1280 ? "collapsed" : "expanded";
}

export function UiStateProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(initialTheme);
  const [sidebarMode, setSidebarModeState] = useState<SidebarMode>(initialSidebarMode);

  // Apply the theme class on every change.
  useEffect(() => { applyTheme(theme); }, [theme]);

  // Auto-collapse the sidebar when the viewport shrinks past the laptop
  // breakpoint — but only when the user is currently 'expanded'. If they
  // explicitly hid it we leave their choice alone.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const mq = window.matchMedia("(max-width: 1279px)");
    const onChange = () => {
      setSidebarModeState((current) => {
        if (mq.matches && current === "expanded") return "collapsed";
        if (!mq.matches && current === "collapsed") return "expanded";
        return current;
      });
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const value = useMemo<UiStateValue>(() => ({
    theme,
    setTheme: setThemeState,
    toggleTheme: () => setThemeState((t) => (t === "dark" ? "light" : "dark")),
    sidebarMode,
    setSidebarMode: setSidebarModeState,
    // Two-state toggle — single click always swaps between expanded and
    // collapsed. No 'hidden' intermediate state to traverse.
    cycleSidebar: () => setSidebarModeState((m) =>
      m === "expanded" ? "collapsed" : "expanded"
    ),
  }), [theme, sidebarMode]);

  return (
    <UiStateContext.Provider value={value}>
      {children}
    </UiStateContext.Provider>
  );
}

export function useUiState(): UiStateValue {
  const ctx = useContext(UiStateContext);
  if (!ctx) throw new Error("useUiState must be used within <UiStateProvider>");
  return ctx;
}
