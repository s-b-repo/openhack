const logo = {
  left: ["                   ", "█▀▀█ █▀▀█ █▀▀█ █▀▀▄", "█__█ █__█ █^^^ █__█", "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀~~▀"],
  right: ["                   ", "█__█ █▀▀█ █▀▀▀ █_▄▀", "█^^█ █^^█ █___ █▄▀_", "▀__▀ ▀__▀ ▀▀▀▀ ▀_▀▄"],
}

const reset = "\x1b[0m"
const bold = "\x1b[1m"
const dim = "\x1b[90m"
// Widow red — dim red for the "OPEN" half, bright red for the "HACK" half.
const redDim = "\x1b[38;5;124m"
const redBright = "\x1b[38;5;196m"

function wordmark(pad = "") {
  const draw = (line: string, fg: string, shadow: string, bg: string) =>
    [...line]
      .map((char) => {
        if (char === "_") return `${bg} ${reset}`
        if (char === "^") return `${fg}${bg}▀${reset}`
        if (char === "~") return `${shadow}▀${reset}`
        if (char === " ") return " "
        return `${fg}${char}${reset}`
      })
      .join("")

  return logo.left.map((line, index) => {
    const left = draw(line, redDim, "\x1b[38;5;52m", "\x1b[48;5;52m")
    const right = draw(logo.right[index] ?? "", redBright, "\x1b[38;5;88m", "\x1b[48;5;88m")
    return `${pad}${left} ${right}`
  })
}

export function sessionEpilogue(input: { title: string; sessionID?: string }) {
  const weak = (text: string) => `${dim}${text.padEnd(10, " ")}${reset}`
  return [
    ...wordmark("  "),
    "",
    `  ${weak("Session")}${bold}${input.title}${reset}`,
    `  ${weak("Continue")}${bold}openhack -s ${input.sessionID}${reset}`,
    "",
  ].join("\n")
}
