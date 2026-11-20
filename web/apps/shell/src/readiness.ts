// Readiness check (contract M0 §7: GET /readyz is 200 only when every barrier passes, else 503 problem).
import { ApiError, RetryPolicy, synthesizeProblem, type ApiClient, type Problem } from "@cs/sdk";

export type Readiness = { readonly state: "ready"; readonly requestId: string | undefined } | { readonly state: "not_ready"; readonly problem: Problem };

/** Readiness polls retry briefly; the user can re-check manually. */
export const READINESS_RETRY = new RetryPolicy({ maxAttempts: 3 });

export async function checkReadiness(client: ApiClient, signal?: AbortSignal): Promise<Readiness> {
  try {
    // The success body is not part of the M0 contract; only the status matters.
    const res = await client.get("/readyz", { retry: READINESS_RETRY, timeoutMs: 10_000, decode: () => undefined, ...(signal && { signal }) });
    return { state: "ready", requestId: res.requestId };
  } catch (e) {
    if (e instanceof ApiError) return { state: "not_ready", problem: e.problem };
    if (signal?.aborted) throw e;
    // Anything else (a programming error) is still reported through the error model, without internals.
    return { state: "not_ready", problem: synthesizeProblem("internal", { instance: "/readyz" }) };
  }
}
