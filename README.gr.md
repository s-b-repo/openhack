<p align="center">
  <a href="https://cybersec.org.za">
    <picture>
      <source srcset="packages/console/app/src/asset/logo-ornate-dark.svg" media="(prefers-color-scheme: dark)">
      <source srcset="packages/console/app/src/asset/logo-ornate-light.svg" media="(prefers-color-scheme: light)">
      <img src="packages/console/app/src/asset/logo-ornate-light.svg" alt="OpenHack logo">
    </picture>
  </a>
</p>
<p align="center">Ο πράκτορας τεχνητής νοημοσύνης ανοικτού κώδικα για προγραμματισμό.</p>
<p align="center">
  <a href="https://cybersec.org.za/discord"><img alt="Discord" src="https://img.shields.io/discord/1391832426048651334?style=flat-square&label=discord" /></a>
  <a href="https://www.npmjs.com/package/openhack-ai"><img alt="npm" src="https://img.shields.io/npm/v/openhack-ai?style=flat-square" /></a>
  <a href="https://github.com/anomalyco/openhack/actions/workflows/publish.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/anomalyco/openhack/publish.yml?style=flat-square&branch=dev" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.zht.md">繁體中文</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="README.de.md">Deutsch</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.fr.md">Français</a> |
  <a href="README.it.md">Italiano</a> |
  <a href="README.da.md">Dansk</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.pl.md">Polski</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.bs.md">Bosanski</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.no.md">Norsk</a> |
  <a href="README.br.md">Português (Brasil)</a> |
  <a href="README.th.md">ไทย</a> |
  <a href="README.tr.md">Türkçe</a> |
  <a href="README.uk.md">Українська</a> |
  <a href="README.bn.md">বাংলা</a> |
  <a href="README.gr.md">Ελληνικά</a> |
  <a href="README.vi.md">Tiếng Việt</a>
</p>

[![OpenHack Terminal UI](packages/web/src/assets/lander/screenshot.png)](https://cybersec.org.za)

---

### Εγκατάσταση

```bash
# YOLO
curl -fsSL https://cybersec.org.za/install | bash

# Διαχειριστές πακέτων
npm i -g openhack-ai@latest        # ή bun/pnpm/yarn
scoop install openhack             # Windows
choco install openhack             # Windows
brew install anomalyco/tap/openhack # macOS και Linux (προτείνεται, πάντα ενημερωμένο)
brew install openhack              # macOS και Linux (επίσημος τύπος brew, λιγότερο συχνές ενημερώσεις)
sudo pacman -S openhack            # Arch Linux (Σταθερό)
paru -S openhack-bin               # Arch Linux (Τελευταία έκδοση από AUR)
mise use -g openhack               # Οποιοδήποτε λειτουργικό σύστημα
nix run nixpkgs#openhack           # ή github:anomalyco/openhack με βάση την πιο πρόσφατη αλλαγή από το dev branch
```

> [!TIP]
> Αφαίρεσε παλαιότερες εκδόσεις από τη 0.1.x πριν από την εγκατάσταση.

### Εφαρμογή Desktop (BETA)

Το OpenHack είναι επίσης διαθέσιμο ως εφαρμογή. Κατέβασε το απευθείας από τη [σελίδα εκδόσεων](https://github.com/anomalyco/openhack/releases) ή το [cybersec.org.za/download](https://cybersec.org.za/download).

| Πλατφόρμα             | Λήψη                               |
| --------------------- | ---------------------------------- |
| macOS (Apple Silicon) | `openhack-desktop-mac-arm64.dmg`   |
| macOS (Intel)         | `openhack-desktop-mac-x64.dmg`     |
| Windows               | `openhack-desktop-windows-x64.exe` |
| Linux                 | `.deb`, `.rpm`, ή AppImage         |

```bash
# macOS (Homebrew)
brew install --cask openhack-desktop
# Windows (Scoop)
scoop bucket add extras; scoop install extras/openhack-desktop
```

#### Κατάλογος Εγκατάστασης

Το script εγκατάστασης τηρεί την ακόλουθη σειρά προτεραιότητας για τη διαδρομή εγκατάστασης:

1. `$OPENHACK_INSTALL_DIR` - Προσαρμοσμένος κατάλογος εγκατάστασης
2. `$XDG_BIN_DIR` - Διαδρομή συμβατή με τις προδιαγραφές XDG Base Directory
3. `$HOME/bin` - Τυπικός κατάλογος εκτελέσιμων αρχείων χρήστη (εάν υπάρχει ή μπορεί να δημιουργηθεί)
4. `$HOME/.openhack/bin` - Προεπιλεγμένη εφεδρική διαδρομή

```bash
# Παραδείγματα
OPENHACK_INSTALL_DIR=/usr/local/bin curl -fsSL https://cybersec.org.za/install | bash
XDG_BIN_DIR=$HOME/.local/bin curl -fsSL https://cybersec.org.za/install | bash
```

### Πράκτορες

Το OpenHack περιλαμβάνει δύο ενσωματωμένους πράκτορες μεταξύ των οποίων μπορείτε να εναλλάσσεστε με το πλήκτρο `Tab`.

- **build** - Προεπιλεγμένος πράκτορας με πλήρη πρόσβαση για εργασία πάνω σε κώδικα
- **plan** - Πράκτορας μόνο ανάγνωσης για ανάλυση και εξερεύνηση κώδικα
  - Αρνείται την επεξεργασία αρχείων από προεπιλογή
  - Ζητά άδεια πριν εκτελέσει εντολές bash
  - Ιδανικός για εξερεύνηση άγνωστων αρχείων πηγαίου κώδικα ή σχεδιασμό αλλαγών

Περιλαμβάνεται επίσης ένας **general** υποπράκτορας για σύνθετες αναζητήσεις και πολυβηματικές διεργασίες.
Χρησιμοποιείται εσωτερικά και μπορεί να κληθεί χρησιμοποιώντας `@general` στα μηνύματα.

Μάθετε περισσότερα για τους [πράκτορες](https://cybersec.org.za/docs/agents).

### Οδηγός Χρήσης

Για περισσότερες πληροφορίες σχετικά με τη ρύθμιση του OpenHack, [**πλοηγήσου στον οδηγό χρήσης μας**](https://cybersec.org.za/docs).

### Συνεισφορά

Εάν ενδιαφέρεσαι να συνεισφέρεις στο OpenHack, διαβάστε τα [οδηγό χρήσης συνεισφοράς](./CONTRIBUTING.md) πριν υποβάλεις ένα pull request.

### Δημιουργία πάνω στο OpenHack

Εάν εργάζεσαι σε ένα έργο σχετικό με το OpenHack και χρησιμοποιείτε το "openhack" ως μέρος του ονόματός του, για παράδειγμα "openhack-dashboard" ή "openhack-mobile", πρόσθεσε μια σημείωση στο README σας για να διευκρινίσεις ότι δεν είναι κατασκευασμένο από την ομάδα του OpenHack και δεν έχει καμία σχέση με εμάς.

---

**Γίνε μέλος της κοινότητάς μας** [Discord](https://discord.gg/openhack) | [X.com](https://x.com/openhack)
