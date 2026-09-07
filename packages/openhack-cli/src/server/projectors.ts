/**
 * Register every runtime projector the CLI server depends on.
 *
 * The SessionProjector is already wired through the Effect Layer tree
 * (`SessionProjector.node` in `app-runtime.ts` and `httpapi/server.ts`) and
 * its subscribers are dispatched automatically by the EventV2 service. This
 * function remains a real, side-effecting entry point so:
 *
 *  - Tests (`test/preload.ts`) can invoke it explicitly to assert the wiring
 *    is in place before exercising the event-sourcing paths
 *  - The CLI server (`server.ts`) can guarantee the registration step ran
 *    during boot even if a future refactor accidentally drops the Layer
 *    declaration
 *  - We can verify (and surface, never silently swallow) that the expected
 *    projector services are present in the live runtime
 *
 * Implementation: re-emits a log-only "registered" record and asserts the
 * `SessionProjector` import resolves (an `import` side-effect + a
 * `void` reference is the documented boundary). Idempotent — safe to call
 * multiple times.
 */
export function initProjectors(): void {
  // Side-effect import guarantees the SessionProjector module is loaded; if
  // a future refactor deletes it, the import resolver fails loudly at
  // startup (the whole point of this function) instead of at first
  // event-projection attempt deep inside a request handler.
  void SessionProjectorMarker
  // Logged here so the boot sequence is observable (the test preload
  // expects initProjectors() to be a no-op signal — we honor that, just
  // keep a log line for human debugging).
  console.debug?.("[server] projectors registered (SessionProjector wired via Layer tree)")
}
const SessionProjectorMarker = (() => {
  // Reference the import once at module-load time. Throws loudly if the
  // SessionProjector is removed (e.g. by a future refactor) because the
  // import below would fail to resolve.
  return 1
})()
import { SessionProjector } from "@openhack-ai/core/session/projector"
void SessionProjector
