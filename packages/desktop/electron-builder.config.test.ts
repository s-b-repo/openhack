import { expect, test } from "bun:test"
import type { Configuration } from "electron-builder"

const legacyDesktopEntry = "resources/linux/openhack-desktop.desktop"

const channels = [
  { channel: "dev", appId: "ai.openhack.desktop.dev" },
  { channel: "beta", appId: "ai.openhack.desktop.beta" },
  { channel: "prod", appId: "ai.openhack.desktop" },
] as const

for (const channel of channels) {
  test(`uses one Linux desktop identity for ${channel.channel}`, async () => {
    const previous = process.env.OPENHACK_CHANNEL
    process.env.OPENHACK_CHANNEL = channel.channel

    const module = await import(`./electron-builder.config.ts?channel=${channel.channel}`)
    const config = module.default as Configuration

    if (previous === undefined) delete process.env.OPENHACK_CHANNEL
    else process.env.OPENHACK_CHANNEL = previous

    expect(config.appId).toBe(channel.appId)
    expect(config.extraMetadata?.desktopName).toBe(`${channel.appId}.desktop`)
    expect(config.linux?.executableName).toBe(channel.appId)
    expect(config.linux?.desktop?.entry?.StartupWMClass).toBe(channel.appId)
  })
}

test("keeps a hidden prod launcher for old Linux pins", async () => {
  const previous = process.env.OPENHACK_CHANNEL
  process.env.OPENHACK_CHANNEL = "prod"

  const module = await import("./electron-builder.config.ts?compat=prod")
  const config = module.default as Configuration

  if (previous === undefined) delete process.env.OPENHACK_CHANNEL
  else process.env.OPENHACK_CHANNEL = previous

  expect(config.deb?.fpm?.[0]).toEndWith(`${legacyDesktopEntry}=/usr/share/applications/openhack-desktop.desktop`)
  expect(config.rpm?.fpm?.[0]).toEndWith(`${legacyDesktopEntry}=/usr/share/applications/openhack-desktop.desktop`)

  const desktop = await Bun.file(legacyDesktopEntry).text()
  expect(desktop).toContain("Exec=/opt/OpenHack/ai.openhack.desktop %U")
  expect(desktop).toContain("Icon=ai.openhack.desktop")
  expect(desktop).toContain("StartupWMClass=ai.openhack.desktop")
  expect(desktop).toContain("NoDisplay=true")
})
