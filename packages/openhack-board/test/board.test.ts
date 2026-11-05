import { describe, expect, test } from "bun:test"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { Project, Identity, GENESIS } from "../src/board"

function tmp(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix))
}

describe("config", () => {
  test("init, perms, round-trip, key masking, env resolution", () => {
    const root = tmp("ohb-cfg-")
    const p = new Project(root).initDefaults()
    expect(fs.existsSync(p.configPath)).toBe(true)
    const mode = fs.statSync(p.configPath).mode & 0o777
    expect(mode).toBe(0o600)
    expect(p.getAgent("main")).toBeDefined()
    expect(p.agents["recon"]).toBeDefined()

    p.main.provider = "anthropic"
    p.main.model = "claude-opus-5-5"
    p.main.apiKey = "env:ANTHROPIC_API_KEY"
    p.agents["recon"].apiKey = "sk-literal-secret-abcd"
    p.save()

    const p2 = new Project(root).load()
    expect(p2.main.model).toBe("claude-opus-5-5")
    expect(p2.agents["recon"].apiKey.endsWith("abcd")).toBe(true)

    const { keyDisplay, resolvedKey } = require("../src/board")
    const disp = keyDisplay(p2.agents["recon"])
    expect(disp).toContain("abcd")
    expect(disp).not.toContain("sk-literal")

    process.env.ANTHROPIC_API_KEY = "sk-env-value"
    expect(resolvedKey(p2.main)).toBe("sk-env-value")
    delete process.env.ANTHROPIC_API_KEY
    expect(resolvedKey(p2.main)).toBeNull()
  })
})

describe("identities", () => {
  test("persist 0600, stable across loads", () => {
    const p = new Project(tmp("ohb-id-")).initDefaults()
    const a = p.identity("recon")
    const keyFile = path.join(p.keysDir, "recon.key")
    expect(fs.existsSync(keyFile)).toBe(true)
    expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600)
    expect(p.identity("recon").pubSpki()).toBe(a.pubSpki())
  })
})

describe("board sign/verify + tamper detection", () => {
  test("clean board verifies", () => {
    const p = new Project(tmp("ohb-ok-")).initDefaults()
    p.post("main", "Engagement started. Scope 10.10.0.0/16.")
    p.post("recon", "Open 22,80,443 on 10.10.0.5.")
    p.post("exploit", "SQLi confirmed on /login.")
    const res = p.verifyBoard()
    expect(res.length).toBe(3)
    expect(res.every((r) => r.ok)).toBe(true)
  })

  test("editing a body fails signature and breaks the chain after it", () => {
    const p = new Project(tmp("ohb-edit-")).initDefaults()
    p.post("main", "one"); p.post("recon", "two"); p.post("exploit", "three")
    const lines = fs.readFileSync(p.boardPath, "utf8").trim().split("\n")
    const m1 = JSON.parse(lines[1]); m1.body = "TAMPERED"; lines[1] = JSON.stringify(m1)
    fs.writeFileSync(p.boardPath, lines.join("\n") + "\n")
    const res = p.verifyBoard()
    expect(res[1].ok).toBe(false)
    expect(res[1].reason).toContain("bad signature")
    expect(res[2].ok).toBe(false)
    expect(res[2].reason).toContain("chain")
  })

  test("dropping a message breaks the chain", () => {
    const p = new Project(tmp("ohb-drop-")).initDefaults()
    p.post("main", "one"); p.post("main", "two"); p.post("main", "three")
    const g = fs.readFileSync(p.boardPath, "utf8").trim().split("\n")
    fs.writeFileSync(p.boardPath, g[0] + "\n" + g[2] + "\n") // drop the middle
    const res = p.verifyBoard()
    expect(res.some((r) => !r.ok)).toBe(true)
  })

  test("a corrupt/garbage appended line is a failure, not a crash (no evasion)", () => {
    const p = new Project(tmp("ohb-corrupt-")).initDefaults()
    p.post("main", "legit one")
    fs.appendFileSync(p.boardPath, "this is not json{{{\n") // attacker appends junk
    const res = p.verifyBoard() // must not throw
    expect(res.length).toBe(2)
    expect(res[0].ok).toBe(true)
    expect(res[1].ok).toBe(false)
    expect(res[1].reason).toContain("unparseable")
  })

  test("rejects path-traversal agent names, and verify never escapes/crashes", () => {
    const p = new Project(tmp("ohb-trav-")).initDefaults()
    expect(() => p.addAgent("../../evil")).toThrow()
    expect(() => p.addAgent("a/b")).toThrow()
    expect(() => p.identity("../../evil")).toThrow()
    // a crafted entry with a traversal author must not throw or write files on verify
    const atk = Identity.generate()
    const author = "../../evil", seq = 0, prev = GENESIS, ts = "2026-01-01T00:00:00Z", pubkey = atk.pubSpki()
    const data = Buffer.from(JSON.stringify({ seq, ts, author, body: "x", prev, pubkey }), "utf8")
    fs.mkdirSync(p.dir, { recursive: true })
    fs.writeFileSync(p.boardPath, JSON.stringify({ seq, ts, author, body: "x", prev, pubkey, sig: atk.sign(data) }) + "\n")
    expect(() => p.verifyBoard()).not.toThrow()
    expect(fs.existsSync(path.join(p.root, "..", "evil.key"))).toBe(false)
  })

  test("concurrent posts are serialised (unique seqs, chain intact)", async () => {
    const p = new Project(tmp("ohb-conc-")).initDefaults()
    // pre-create identities so key generation doesn't race the lock test
    p.identity("main")
    await Promise.all(
      Array.from({ length: 12 }, (_, i) => Promise.resolve().then(() => p.post("main", `m${i}`))),
    )
    const res = p.verifyBoard()
    expect(res.length).toBe(12)
    expect(res.every((r) => r.ok)).toBe(true)
    expect(new Set(res.map((r) => r.msg.seq)).size).toBe(12) // no duplicate seq
  })

  test("forged author (valid sig, wrong identity) is rejected", () => {
    const p = new Project(tmp("ohb-forge-")).initDefaults()
    p.identity("recon") // register recon's real key
    const attacker = Identity.generate()
    const seq = 0, prev = GENESIS, ts = "2026-01-01T00:00:00Z", pubkey = attacker.pubSpki()
    const data = Buffer.from(JSON.stringify({ seq, ts, author: "recon", body: "backdoor added", prev, pubkey }), "utf8")
    const msg = { seq, ts, author: "recon", body: "backdoor added", prev, pubkey, sig: attacker.sign(data) }
    fs.mkdirSync(p.dir, { recursive: true })
    fs.writeFileSync(p.boardPath, JSON.stringify(msg) + "\n")
    const res = p.verifyBoard()
    expect(res[0].ok).toBe(false)
    expect(res[0].reason).toContain("registered identity")
  })
})
