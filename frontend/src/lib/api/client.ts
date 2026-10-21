import createClient, { type Middleware } from "openapi-fetch";
import { readCookie } from "@/lib/cookies";
import { getActiveTenantId } from "@/lib/tenant";
import type { paths } from "./schema";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const context: Middleware = {
  onRequest({ request }) {
    const tenantId = getActiveTenantId();
    if (tenantId) request.headers.set("X-Tenant-ID", tenantId);
    if (!SAFE_METHODS.has(request.method)) {
      const csrf = readCookie("csrftoken");
      if (csrf) request.headers.set("X-CSRFToken", csrf);
    }
    return request;
  },
};

// Typed end to end: paths come from the backend's OpenAPI contract (npm run gen:api).
export const api = createClient<paths>({ credentials: "include" });
api.use(context);
