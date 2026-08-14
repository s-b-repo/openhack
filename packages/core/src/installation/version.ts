declare global {
  const OPENHACK_VERSION: string
  const OPENHACK_CHANNEL: string
}

export const InstallationVersion = typeof OPENHACK_VERSION === "string" ? OPENHACK_VERSION : "local"
export const InstallationChannel = typeof OPENHACK_CHANNEL === "string" ? OPENHACK_CHANNEL : "local"
export const InstallationLocal = InstallationChannel === "local"
