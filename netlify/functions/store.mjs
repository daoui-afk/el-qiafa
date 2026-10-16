import { getStore } from "@netlify/blobs";import { createHash, timingSafeEqual } from "node:crypto";
const J = (o, s = 200) =>  new Response(JSON.stringify(o), {    status: s,    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },  });const h = (x) => createHash("sha256").update("qiafa-salt|" + x).digest("hex");const same = (a, b) => {  const x = Buffer.from(a), y = Buffer.from(b);  return x.length === y.length && timingSafeEqual(x, y);};
export default async (req) => {  const store = getStore("shop");  const auth = await store.get("auth");
  if (req.method === "GET") {    const state = await store.get("state", { type: "json" });    return J({ state: state || null, hasPw: !!auth });  }  if (req.method !== "POST") return J({ error: "method" }, 405);
  let b;  try { b = await req.json(); } catch { return J({ error: "bad" }, 400); }
  const ph = String(b.ph || "");  if (!ph) return J({ error: "auth" }, 401);  if (auth && !same(h(ph), auth)) return J({ error: "auth" }, 401);
  if (b.action === "login") return J({ ok: true });
  if (b.action === "save") {    const st = b.state;    if (!st || !Array.isArray(st.products)) return J({ error: "bad state" }, 400);    if (st.cfg) delete st.cfg.ph;    await store.setJSON("state", st);    if (!auth || b.newPh) await store.set("auth", h(String(b.newPh || ph)));    return J({ ok: true });  }  return J({ error: "action" }, 400);};
export const config = { path: "/api/store" };
