import {
  FrameBufferRenderable,
  RGBA,
  type OptimizedBuffer,
  type RenderContext,
  type RenderableOptions,
} from "@opentui/core"
import { extend, useRenderer, useTerminalDimensions } from "@opentui/solid"
import { onCleanup, onMount, Show } from "solid-js"
import { useTheme } from "../context/theme"
import { RedWidowPainter } from "./red-widow-render"
import { Logo } from "./logo"

// Fixed banner box — wide enough for the 39-col OPENHACK wordmark, tall enough
// for the spider to travel up and down the thread above it.
const BANNER_W = 44
const BANNER_H = 16

type RedWidowArtOptions = RenderableOptions<FrameBufferRenderable> & {
  background?: RGBA
}

class RedWidowArtRenderable extends FrameBufferRenderable {
  private painter = new RedWidowPainter()

  constructor(ctx: RenderContext, options: RedWidowArtOptions = {}) {
    const width = typeof options.width === "number" ? options.width : 1
    const height = typeof options.height === "number" ? options.height : 1
    super(ctx, { ...options, width, height, live: options.live ?? true, respectAlpha: false })
    if (options.width !== undefined && typeof options.width !== "number") this.width = options.width
    if (options.height !== undefined && typeof options.height !== "number") this.height = options.height
    this.painter.setBackground(options.background)
  }

  set background(value: RGBA | undefined) {
    if (this.painter.setBackground(value)) this.requestRender()
  }

  protected override renderSelf(buffer: OptimizedBuffer, deltaTime = 0): void {
    if (!this.visible || this.isDestroyed) return
    this.painter.render(this.frameBuffer, deltaTime)
    super.renderSelf(buffer)
  }
}

declare module "@opentui/solid" {
  interface OpenTUIComponents {
    red_widow_art: typeof RedWidowArtRenderable
  }
}

extend({ red_widow_art: RedWidowArtRenderable })

/**
 * Animated home banner: a glowing red widow climbing a silk thread above the
 * OPENHACK wordmark. Falls back to the static `<Logo />` when the terminal is
 * too small to show the animation (and restores the renderer FPS on unmount).
 */
export function RedWidow() {
  const { theme } = useTheme()
  const renderer = useRenderer()
  const dimensions = useTerminalDimensions()
  const roomy = () => dimensions().width >= BANNER_W + 2 && dimensions().height >= BANNER_H + 6

  let targetFps = renderer.targetFps
  let maxFps = renderer.maxFps
  onMount(() => {
    targetFps = renderer.targetFps
    maxFps = renderer.maxFps
    renderer.targetFps = 30
    renderer.maxFps = 30
  })
  onCleanup(() => {
    renderer.targetFps = targetFps
    renderer.maxFps = maxFps
  })

  return (
    <Show when={roomy()} fallback={<Logo />}>
      <box width={BANNER_W} height={BANNER_H} flexShrink={0}>
        <red_widow_art width="100%" height="100%" background={theme.background} live />
      </box>
    </Show>
  )
}
