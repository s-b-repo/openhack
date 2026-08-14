export * from "./client.js"
export * from "./server.js"

import { createOpenhackClient } from "./client.js"
import { createOpenhackServer } from "./server.js"
import type { ServerOptions } from "./server.js"

export async function createOpenhack(options?: ServerOptions) {
  const server = await createOpenhackServer({
    ...options,
  })

  const client = createOpenhackClient({
    baseUrl: server.url,
  })

  return {
    client,
    server,
  }
}
