// Wordmark glyphs. `left` spells OPEN, `right` spells HACK → rendered together
// they read OPENHACK. Built from the same half-block vocabulary the renderers
// understand (`█ ▀ ▄` strokes + `_ ^ ~ ,` shadow sentinels), so logo.tsx,
// splash.ts `cells()`, ui.ts `draw()` and presentation.ts `wordmark()` all keep
// translating it unchanged.
export const logo = {
  left: ["                   ", "█▀▀█ █▀▀█ █▀▀█ █▀▀▄", "█__█ █__█ █^^^ █__█", "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀~~▀"],
  right: ["                   ", "█__█ █▀▀█ █▀▀▀ █_▄▀", "█^^█ █^^█ █___ █▄▀_", "▀__▀ ▀__▀ ▀▀▀▀ ▀_▀▄"],
}

export const go = {
  left: ["    ", "█▀▀▀", "█_^█", "▀▀▀▀"],
  right: ["    ", "█▀▀█", "█__█", "▀▀▀▀"],
}

export const marks = "_^~,"
