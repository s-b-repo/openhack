import { RGBA, TextAttributes } from "@opentui/core"
import { For, type JSX } from "solid-js"
import { tint, useTheme } from "../context/theme"
import { logo } from "../logo"

// Widow palette — the OPENHACK wordmark renders red regardless of the active
// theme (the left "OPEN" half a touch dimmer than the bright "HACK" half).
const WIDOW_RED = RGBA.fromInts(220, 40, 45)
const WIDOW_RED_DIM = RGBA.fromInts(150, 28, 32)

export function Logo() {
  const { theme } = useTheme()

  const renderLine = (line: string, fg: RGBA, bold: boolean): JSX.Element[] => {
    const shadow = tint(theme.background, fg, 0.25)
    const attrs = bold ? TextAttributes.BOLD : undefined
    return Array.from(line).map((char) => {
      if (char === "_") {
        return (
          <text fg={fg} bg={shadow} attributes={attrs} selectable={false}>
            {" "}
          </text>
        )
      }
      if (char === "^") {
        return (
          <text fg={fg} bg={shadow} attributes={attrs} selectable={false}>
            ▀
          </text>
        )
      }
      if (char === "~") {
        return (
          <text fg={shadow} attributes={attrs} selectable={false}>
            ▀
          </text>
        )
      }
      if (char === ",") {
        return (
          <text fg={shadow} attributes={attrs} selectable={false}>
            ▄
          </text>
        )
      }
      return (
        <text fg={fg} attributes={attrs} selectable={false}>
          {char}
        </text>
      )
    })
  }

  return (
    <box>
      <For each={logo.left}>
        {(line, index) => (
          <box flexDirection="row" gap={1}>
            <box flexDirection="row">{renderLine(line, WIDOW_RED_DIM, false)}</box>
            <box flexDirection="row">{renderLine(logo.right[index()], WIDOW_RED, true)}</box>
          </box>
        )}
      </For>
    </box>
  )
}
