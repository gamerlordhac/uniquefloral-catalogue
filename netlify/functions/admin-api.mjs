import { getStore } from "@netlify/blobs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const store = getStore("unique-floral-catalogue");
const cookieName = "uf_admin_session";
const defaultCatalogue = {
  title: "Unique Floral",
  intro: "Thoughtfully made flowers, arranged by hand. Find something lovely at a price that feels right.",
  whatsappNumber: "233204341041",
  products: [],
};
const enc = (value) => Buffer.from(value).toString("base64url");
const sign = (payload, secret) => createHmac("sha256", secret).update(payload).digest("base64url");

function getCookie(request) {
  const cookies = request.headers.get("cookie") || "";
  const item = cookies.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${cookieName}=`));
  return item ? decodeURIComponent(item.slice(cookieName.length + 1)) : "";
}
function validSession(request, password) {
  try {
    const [payload, signature] = getCookie(request).split(".");
    if (!payload || !signature) return false;
    const supplied = Buffer.from(signature);
    const expected = Buffer.from(sign(payload, password));
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return false;
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data.exp > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
}
function safeOrigin(request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

export default async (request) => {
  const url = new URL(request.url);
  const action = url.searchParams.get("action") || "";
  const password = process.env.ADMIN_PASSWORD || "";

  if (request.method === "GET" && url.searchParams.has("image")) {
    const name = url.searchParams.get("image");
    if (!/^[a-z0-9-]+\.(png|jpe?g|webp|gif)$/i.test(name || "")) return new Response("Not found", { status: 404 });
    const bytes = await store.get(`images/${name}`, { type: "arrayBuffer" });
    if (!bytes) return new Response("Not found", { status: 404 });
    const ext = name.split(".").pop().toLowerCase();
    const type = ext === "jpg" || ext === "jpeg" ? "image/jpeg" : `image/${ext}`;
    return new Response(bytes, { headers: { "content-type": type, "cache-control": "public, max-age=31536000, immutable" } });
  }

  if (request.method === "GET" && action === "catalogue") {
    const data = await store.get("catalogue.json", { type: "json" });
    return json(data || defaultCatalogue);
  }

  if (request.method === "GET" && action === "session") {
    return json({ configured: Boolean(password), authenticated: Boolean(password && validSession(request, password)) }, password ? 200 : 503);
  }

  if (request.method === "POST" && action === "login") {
    if (!password) return json({ error: "Admin password has not been configured in Netlify." }, 503);
    if (!safeOrigin(request)) return json({ error: "Request not allowed." }, 403);
    const body = await request.json().catch(() => ({}));
    const supplied = createHash("sha256").update(String(body.password || "")).digest();
    const expected = createHash("sha256").update(password).digest();
    if (!timingSafeEqual(supplied, expected)) return json({ error: "That password didn’t match. Please try again." }, 401);
    const payload = enc(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 86400, nonce: randomBytes(12).toString("hex") }));
    const token = `${payload}.${sign(payload, password)}`;
    return json({ ok: true }, 200, { "set-cookie": `${cookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400` });
  }

  if (request.method === "POST" && action === "logout") {
    return json({ ok: true }, 200, { "set-cookie": `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
  }

  if (!password) return json({ error: "Admin password has not been configured in Netlify." }, 503);
  if (!validSession(request, password)) return json({ error: "Please unlock the admin page first." }, 401);
  if (!safeOrigin(request)) return json({ error: "Request not allowed." }, 403);

  if (request.method === "PUT" && action === "catalogue") {
    const data = await request.json().catch(() => null);
    if (!data || !Array.isArray(data.products)) return json({ error: "Catalogue data is invalid." }, 400);
    data.title = String(data.title || "Unique Floral").slice(0, 100);
    data.intro = String(data.intro || "").slice(0, 500);
    data.whatsappNumber = String(data.whatsappNumber || "").replace(/\D/g, "").slice(0, 20);
    data.products = data.products.slice(0, 500).map((p) => ({
      name: String(p.name || "").slice(0, 120),
      price: Math.max(0, Number(p.price) || 0),
      category: String(p.category || "Bouquet").slice(0, 60),
      description: String(p.description || "").slice(0, 1000),
      image: String(p.image || "").slice(0, 300),
    })).filter((p) => p.name);
    await store.setJSON("catalogue.json", data);
    return json({ ok: true });
  }

  if (request.method === "POST" && action === "image") {
    const body = await request.json().catch(() => ({}));
    const allowed = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif" };
    const ext = allowed[body.type];
    if (!ext || typeof body.data !== "string" || body.data.length > 7_000_000) return json({ error: "Choose a PNG, JPG, WEBP, or GIF photo under 5 MB." }, 400);
    const name = `${randomBytes(12).toString("hex")}.${ext}`;
    await store.set(`images/${name}`, Buffer.from(body.data, "base64"));
    return json({ image: `/.netlify/functions/admin-api?image=${name}` });
  }

  return json({ error: "Not found." }, 404);
};




