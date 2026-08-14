interface ImportMetaEnv {
  readonly OPENHACK_CHANNEL: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare module "virtual:openhack-server" {
  export namespace Server {
    export const listen: typeof import("../../../openhack-cli/dist/types/src/node").Server.listen
    export type Listener = import("../../../openhack-cli/dist/types/src/node").Server.Listener
  }
  export namespace Config {
    export const get: typeof import("../../../openhack-cli/dist/types/src/node").Config.get
    export type Info = import("../../../openhack-cli/dist/types/src/node").Config.Info
  }
  export const bootstrap: typeof import("../../../openhack-cli/dist/types/src/node").bootstrap
}
