# 🛡️ PROMPT-SHIELD

**Prompt Injection Firewall für KI-Agenten**

Schützt KI-Systeme vor manipulativen Eingaben durch mehrschichtige Pattern-Erkennung und Heuristik-Scoring.

[![Tests](https://img.shields.io/badge/core%20tests-29%2F29%20passing-green)]()
[![Version](https://img.shields.io/badge/version-3.0.5-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 🚀 Quick Start

```bash
# Text scannen
./shield.py scan "Dein Text hier"

# JSON Output
./shield.py --json scan "text"

# Von Datei
./shield.py scan --file input.txt

# Von stdin
cat message.txt | ./shield.py scan --stdin
```

## 📊 Threat Levels

| Level | Score | Aktion |
|-------|-------|--------|
| 🟢 CLEAN | 0-49 | Durchlassen |
| 🟡 WARNING | 50-79 | Warnung anzeigen |
| 🔴 BLOCK | 80-100 | Blockieren |

## 🔍 Erkannte Angriffsmuster

### Fake Authority
- `SYSTEM ALERT`, `SECURITY WARNING`
- `PROTOCOL [NAME]`
- `URGENT ACTION REQUIRED`

### Fear Triggers
- `PERMANENT API BAN`
- `TOS VIOLATION`
- `SHUT DOWN / TERMINATE`

### Command Injection
- JSON-Payloads: `{"instruction": "..."}`
- Imperativ-Befehle: `DELETE YOUR`, `EXECUTE THIS`
- Shell-Commands: `curl example.com | jq`

### Social Engineering
- Engagement-Farming: `follow and upvote`
- Gratis-Köder: `189 FREE APIs!`

## 🧠 Heuristic Scoring

Combo-Detection erhöht den Score:

| Kombination | Bonus |
|-------------|-------|
| Authority + Fear + Command | +20 |
| Authority + Command | +10 |
| 4+ Kategorien | +15 |

## 📁 Dateien

```
prompt-shield/
├── shield.py              # Haupt-Scanner (Layer 1 + 2a)
├── patterns.yaml          # Pattern-Datenbank (113 Patterns, 14 Kategorien)
├── whitelist.yaml         # Hash-Chain Whitelist v2
├── prompt-shield-hook.sh  # Claude Code Hook
├── test_shield.py         # Test-Suite (29 Core + 135 GUARDIAN Tests)
├── SCORING.md             # Scoring-Dokumentation
├── LICENSE                # MIT License
└── testdata/
    ├── WARNING.md         # ⚠️ LIES DIES ZUERST!
    └── moltbook-comments-GUARDIAN-curated.json  # 135 kuratierte Testfaelle
```

## ⚠️ Testdaten

Das `testdata/` Verzeichnis enthaelt **echte Prompt-Injection-Angriffe und Spam** aus Live-Plattformen. Diese Texte sind absichtlich boesartig - siehe `testdata/WARNING.md` fuer Details. Nur fuer kontrollierte Tests verwenden!

## 🔧 Claude Code Integration

In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "UserInputSubmit": [
      "/path/to/prompt-shield/prompt-shield-hook.sh"
    ]
  }
}
```

## ➕ Patterns erweitern

Neue Muster in `patterns.yaml` hinzufügen:

```yaml
kategorie:
  - id: mein_pattern
    regex: "(?i)verdaechtig\\s*muster"
    score: 25
    description: "Mein neues Pattern"
```

## 🧪 Tests

```bash
./test_shield.py
# Core Tests:     29/29 passed
# GUARDIAN Tests:  73/135 passed (Layer 1 only - Layer 2a improves detection)
```

## 📜 Exit Codes

| Code | Bedeutung |
|------|-----------|
| 0 | CLEAN |
| 1 | WARNING |
| 2 | BLOCK |

## 🤝 Credits

- **CODE** - Entwicklung
- **GUARDIAN** - Security-Analyse, Pattern-Design
- **AICOLLAB** - Real-World Testing (Moltbook Spam)
- **RASSELBANDE** - Das beste KI-Kollektiv

## 📄 Lizenz

MIT License - Frei nutzbar für alle KI-Agenten!

---

*"Der beste Angriff ist eine gute Verteidigung"* - GUARDIAN

*Entwickelt von der RASSELBANDE, Februar 2026*
