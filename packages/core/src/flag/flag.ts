import { Config } from "effect"

export function truthy(key: string) {
  const value = process.env[key]?.toLowerCase()
  return value === "true" || value === "1"
}

const copy = process.env["OPENHACK_EXPERIMENTAL_DISABLE_COPY_ON_SELECT"]
const fff = process.env["OPENHACK_DISABLE_FFF"]

function enabledByExperimental(key: string) {
  return process.env[key] === undefined ? truthy("OPENHACK_EXPERIMENTAL") : truthy(key)
}

export const Flag = {
  OTEL_EXPORTER_OTLP_ENDPOINT: process.env["OTEL_EXPORTER_OTLP_ENDPOINT"],
  OTEL_EXPORTER_OTLP_HEADERS: process.env["OTEL_EXPORTER_OTLP_HEADERS"],

  OPENHACK_AUTO_HEAP_SNAPSHOT: truthy("OPENHACK_AUTO_HEAP_SNAPSHOT"),
  OPENHACK_GIT_BASH_PATH: process.env["OPENHACK_GIT_BASH_PATH"],
  OPENHACK_CONFIG: process.env["OPENHACK_CONFIG"],
  OPENHACK_CONFIG_CONTENT: process.env["OPENHACK_CONFIG_CONTENT"],
  OPENHACK_DISABLE_AUTOUPDATE: truthy("OPENHACK_DISABLE_AUTOUPDATE"),
  OPENHACK_ALWAYS_NOTIFY_UPDATE: truthy("OPENHACK_ALWAYS_NOTIFY_UPDATE"),
  OPENHACK_DISABLE_PRUNE: truthy("OPENHACK_DISABLE_PRUNE"),
  OPENHACK_DISABLE_TERMINAL_TITLE: truthy("OPENHACK_DISABLE_TERMINAL_TITLE"),
  OPENHACK_SHOW_TTFD: truthy("OPENHACK_SHOW_TTFD"),
  OPENHACK_DISABLE_AUTOCOMPACT: truthy("OPENHACK_DISABLE_AUTOCOMPACT"),
  OPENHACK_DISABLE_MODELS_FETCH: truthy("OPENHACK_DISABLE_MODELS_FETCH"),
  OPENHACK_DISABLE_MOUSE: truthy("OPENHACK_DISABLE_MOUSE"),
  OPENHACK_FAKE_VCS: process.env["OPENHACK_FAKE_VCS"],
  OPENHACK_SERVER_PASSWORD: process.env["OPENHACK_SERVER_PASSWORD"],
  OPENHACK_SERVER_USERNAME: process.env["OPENHACK_SERVER_USERNAME"],
  OPENHACK_DISABLE_FFF: fff === undefined ? process.platform === "win32" : truthy("OPENHACK_DISABLE_FFF"),

  // Experimental
  OPENHACK_EXPERIMENTAL_FILEWATCHER: Config.boolean("OPENHACK_EXPERIMENTAL_FILEWATCHER").pipe(
    Config.withDefault(false),
  ),
  OPENHACK_EXPERIMENTAL_DISABLE_FILEWATCHER: Config.boolean("OPENHACK_EXPERIMENTAL_DISABLE_FILEWATCHER").pipe(
    Config.withDefault(false),
  ),
  OPENHACK_EXPERIMENTAL_DISABLE_COPY_ON_SELECT:
    copy === undefined ? process.platform === "win32" : truthy("OPENHACK_EXPERIMENTAL_DISABLE_COPY_ON_SELECT"),
  OPENHACK_MODELS_URL: process.env["OPENHACK_MODELS_URL"],
  OPENHACK_MODELS_PATH: process.env["OPENHACK_MODELS_PATH"],
  OPENHACK_DB: process.env["OPENHACK_DB"],

  OPENHACK_WORKSPACE_ID: process.env["OPENHACK_WORKSPACE_ID"],
  OPENHACK_EXPERIMENTAL_WORKSPACES: enabledByExperimental("OPENHACK_EXPERIMENTAL_WORKSPACES"),

  // Evaluated at access time (not module load) because tests, the CLI, and
  // external tooling set these env vars at runtime.
  get OPENHACK_DISABLE_PROJECT_CONFIG() {
    return truthy("OPENHACK_DISABLE_PROJECT_CONFIG")
  },
  get OPENHACK_EXPERIMENTAL_REFERENCES() {
    return enabledByExperimental("OPENHACK_EXPERIMENTAL_REFERENCES")
  },
  get OPENHACK_TUI_CONFIG() {
    return process.env["OPENHACK_TUI_CONFIG"]
  },
  get OPENHACK_CONFIG_DIR() {
    return process.env["OPENHACK_CONFIG_DIR"]
  },
  get OPENHACK_PURE() {
    return truthy("OPENHACK_PURE")
  },
  get OPENHACK_PERMISSION() {
    return process.env["OPENHACK_PERMISSION"]
  },
  get OPENHACK_PLUGIN_META_FILE() {
    return process.env["OPENHACK_PLUGIN_META_FILE"]
  },
  get OPENHACK_CLIENT() {
    return process.env["OPENHACK_CLIENT"] ?? "cli"
  },
}
