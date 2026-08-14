// Red-widow home banner painter.
//
// A realistic black-widow spider — RED body, WHITE legs — hangs from a thin
// silk thread, glows (its red brightness pulses), and slowly climbs the thread
// up and down. Below it sits the OPENHACK wordmark in big red block letters
// with a left→right shimmer sweep.
//
// This mirrors the proven animation path used by `bg-pulse-render.ts`
// (`GoUpsellArtPainter`): a `FrameBufferRenderable` drives `render(buffer, dt)`
// every frame at 30 fps, and we paint straight onto the buffer with the
// high-level `OptimizedBuffer` API (`clear`/`fillRect`/`setCell`).
import { OptimizedBuffer, RGBA } from "@opentui/core"

// OPENHACK, big — same half-block letterforms as the CLI wordmark. Plain glyphs
// (no `_ ^ ~` sentinels) so we can colour each column individually for the sweep.
const WORDMARK = [
  "█▀▀█ █▀▀█ █▀▀█ █▀▀▄ █  █ █▀▀█ █▀▀▀ █ ▄▀",
  "█  █ █  █ █▀▀▀ █  █ █▀▀█ █▀▀█ █    █▀▄ ",
  "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀  ▀ ▀  ▀ ▀  ▀ ▀▀▀▀ ▀ ▀▄",
]
const WORDMARK_W = 39

// The spider sprite. Body glyphs (`█▟▙▜▛▀▄`) render red and glow; leg glyphs
// (`╲ ╱ ─`) render white; `▼` is the dark hourglass on the belly.
const SPRITE = [
  "   ▟█▙   ",
  "╲ █████ ╱",
  "──██▼██──",
  "╱ █████ ╲",
  "   ▜█▛   ",
]
const SPRITE_W = 9
const SPRITE_H = SPRITE.length

const CLIMB_PERIOD = 9000 // ms for one full down-and-up cycle (slow)
const GLOW_PERIOD = 2200 // ms for the body glow pulse
const SHIMMER_PERIOD = 3200 // ms for the wordmark sweep
const TAU = Math.PI * 2

type Rgb = [number, number, number]
const BODY_DIM: Rgb = [148, 22, 26]
const BODY_BRIGHT: Rgb = [255, 82, 86]
const LEG: Rgb = [234, 234, 234]
const HOURGLASS: Rgb = [12, 6, 8]
const THREAD: Rgb = [96, 74, 76]

const BODY_GLYPHS = "█▟▙▜▛▀▄"
const LEG_GLYPHS = "╲╱─│"

const clampByte = (n: number) => (n < 0 ? 0 : n > 255 ? 255 : Math.round(n))
const lerp = (a: number, b: number, t: number) => clampByte(a + (b - a) * t)
const mix = (a: Rgb, b: Rgb, t: number): RGBA => RGBA.fromInts(lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t))

export class RedWidowPainter {
  private elapsed = 0
  private bg: RGBA = RGBA.fromInts(0, 0, 0)
  private bgRgb: Rgb = [0, 0, 0]
  private threadColor: RGBA = RGBA.fromInts(THREAD[0], THREAD[1], THREAD[2])
  private legColor: RGBA = RGBA.fromInts(LEG[0], LEG[1], LEG[2])
  private hourglassColor: RGBA = RGBA.fromInts(HOURGLASS[0], HOURGLASS[1], HOURGLASS[2])

  /** Set the panel background (usually `theme.background`). Returns true on change. */
  setBackground(value: RGBA | undefined): boolean {
    if (!value) return false
    const [r, g, b] = value.toInts()
    if (r === this.bgRgb[0] && g === this.bgRgb[1] && b === this.bgRgb[2]) return false
    this.bg = value
    this.bgRgb = [r, g, b]
    return true
  }

  /** True when the buffer is large enough to show the full banner. */
  fits(width: number, height: number): boolean {
    return width >= SPRITE_W + 2 && height >= SPRITE_H + WORDMARK.length + 3
  }

  render(buffer: OptimizedBuffer, deltaTime = 0): void {
    this.elapsed += deltaTime
    const W = buffer.width
    const H = buffer.height
    buffer.clear(this.bg)
    if (!this.fits(W, H)) return

    const cx = Math.floor(W / 2)

    // ── OPENHACK wordmark, pinned to the bottom, with a moving bright band ──
    const wmTop = H - WORDMARK.length
    const wmLeft = Math.max(0, cx - Math.floor(WORDMARK_W / 2))
    const sweep = (this.elapsed % SHIMMER_PERIOD) / SHIMMER_PERIOD
    for (let r = 0; r < WORDMARK.length; r++) {
      const row = WORDMARK[r]!
      for (let c = 0; c < row.length; c++) {
        const ch = row[c]!
        if (ch === " ") continue
        const dist = Math.abs(((c / WORDMARK_W - sweep + 1) % 1))
        const band = Math.max(0, 1 - dist * 6) // narrow highlight band
        buffer.setCell(wmLeft + c, wmTop + r, ch, mix(BODY_DIM, BODY_BRIGHT, 0.35 + 0.6 * band), this.bg)
      }
    }

    // ── spider climb position (eased down-and-up) ──
    const climb = 0.5 - 0.5 * Math.cos(TAU * ((this.elapsed % CLIMB_PERIOD) / CLIMB_PERIOD))
    const travelTop = 1
    const travelBottom = Math.max(travelTop, wmTop - SPRITE_H - 1)
    const spiderTop = Math.round(travelTop + (travelBottom - travelTop) * climb)
    const spriteLeft = cx - Math.floor(SPRITE_W / 2)

    // ── glow factor (drives body brightness + halo) ──
    const glow = 0.5 + 0.5 * Math.sin(TAU * ((this.elapsed % GLOW_PERIOD) / GLOW_PERIOD))
    const bodyColor = mix(BODY_DIM, BODY_BRIGHT, 0.25 + 0.7 * glow)
    const haloBg = mix(this.bgRgb, BODY_DIM, 0.1 + 0.18 * glow)

    // Soft red aura in the gaps between the legs.
    buffer.fillRect(
      Math.max(0, spriteLeft - 1),
      Math.max(0, spiderTop - 1),
      Math.min(W, spriteLeft + SPRITE_W + 1) - Math.max(0, spriteLeft - 1),
      Math.min(H, spiderTop + SPRITE_H + 1) - Math.max(0, spiderTop - 1),
      haloBg,
    )

    // ── silk thread from the very top down to the spider ──
    for (let y = 0; y < spiderTop; y++) buffer.setCell(cx, y, "│", this.threadColor, this.bg)

    // ── the spider ──
    for (let r = 0; r < SPRITE_H; r++) {
      const row = SPRITE[r]!
      for (let c = 0; c < row.length; c++) {
        const ch = row[c]!
        if (ch === " ") continue
        const x = spriteLeft + c
        const y = spiderTop + r
        if (x < 0 || x >= W || y < 0 || y >= H) continue
        if (ch === "▼") buffer.setCell(x, y, ch, this.hourglassColor, bodyColor)
        else if (BODY_GLYPHS.includes(ch)) buffer.setCell(x, y, ch, bodyColor, this.bg)
        else if (LEG_GLYPHS.includes(ch)) buffer.setCell(x, y, ch, this.legColor, this.bg)
        else buffer.setCell(x, y, ch, this.legColor, this.bg)
      }
    }
  }
}
