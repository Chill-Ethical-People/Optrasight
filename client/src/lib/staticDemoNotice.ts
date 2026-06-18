export type StaticDemoNoticeKind = "ai" | "write" | "export" | "source" | "selection" | "default";

export type StaticDemoNoticeDetail = {
  kind?: StaticDemoNoticeKind;
  action?: string;
};

export const STATIC_DEMO_NOTICE_EVENT = "optrasight:static-demo-notice";

export function showStaticDemoNotice(detail: StaticDemoNoticeDetail = {}) {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent<StaticDemoNoticeDetail>(STATIC_DEMO_NOTICE_EVENT, { detail }));
}
