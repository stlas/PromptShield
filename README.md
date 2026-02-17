# PromptShield

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org)
[![Tests](https://img.shields.io/badge/core%20tests-29%2F29%20passing-green)]()
<<<<<<< HEAD
[![Version](https://img.shields.io/badge/version-3.1.0-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
=======
>>>>>>> 7e5634a (v3.1.0: Sanitize internal platform references + update README)

**Prompt Injection Firewall for AI Agents -- 113 detection patterns across 14 categories. Protect your LLM applications.**

PromptShield scans text input for prompt injection attacks, social engineering, and malicious payloads before they reach your AI agent. It uses multi-layer pattern matching with heuristic scoring to classify input as CLEAN, WARNING, or BLOCK.

> PromptShield is one defensive layer in a defense-in-depth strategy. No single security tool provides 100% protection.

## Quick Start

```bash
git clone https://github.com/sTLAs/PromptShield.git && cd PromptShield
pip install pyyaml

# Scan a string
./shield.py scan "Your text here"

# Scan a file
./shield.py scan --file input.txt

# Scan from stdin
cat message.txt | ./shield.py scan --stdin

# JSON output for automation
./shield.py --json scan "text"
```

Exit codes: `0` = CLEAN, `1` = WARNING, `2` = BLOCK.

## What It Detects

113 patterns organized in 14 categories:

| Category | Examples |
|----------|----------|
| **Fake Authority** | `SYSTEM ALERT`, `SECURITY WARNING`, `PROTOCOL [NAME]` |
| **Fear Triggers** | `PERMANENT API BAN`, `TOS VIOLATION`, `SHUT DOWN` |
| **Command Injection** | JSON payloads, imperative commands, shell injection |
| **Social Engineering** | Engagement farming, fake giveaways, identity manipulation |
| **Crypto/Link Spam** | Token promotions, URL obfuscation, phishing links |
| **Skill Malware** | Malicious skill/plugin payloads, supply chain attacks |
| **Memory Poisoning** | Attempts to corrupt agent memory or context |
| **Email Injection** | Header injection, BCC manipulation |
| **Bot Spam** | Repetitive patterns, template-based spam |

Plus: structural anomaly detection, cryptic encoding patterns, and platform-specific injection vectors.

## How It Works

### Multi-Layer Detection

**Layer 1 -- Pattern Matching:**
Each input is scanned against 113 regex patterns. Every match adds to a cumulative threat score weighted by severity.

**Layer 2 -- Heuristic Analysis:**
Combo detection boosts the score when multiple attack categories appear together:

| Combination | Score Bonus |
|-------------|-------------|
| Authority + Fear + Command | +20 |
| Authority + Command | +10 |
| 4+ categories triggered | +15 |

**Context Awareness:**
- Patterns inside code fences (`` ``` ``) get reduced scores -- tutorials and documentation are not attacks
- Educational content (how-to, examples) is detected and scored conservatively
- Unicode confusables (Cyrillic/Greek/fullwidth lookalikes) are normalized before scanning
- Recursive encoding chains (Base64, URL encoding, hex) are decoded up to 3 levels deep

<<<<<<< HEAD
```
prompt-shield/
├── shield.py              # Haupt-Scanner (Layer 1 + 2a)
├── patterns.yaml          # Pattern-Datenbank (113 Patterns, 14 Kategorien)
├── whitelist.yaml         # Hash-Chain Whitelist v2
├── prompt-shield-hook.sh  # Claude Code Hook
├── test_shield.py         # Test-Suite (29 Core + 135 Curated Tests)
├── SCORING.md             # Scoring-Dokumentation
├── LICENSE                # MIT License
└── testdata/
    ├── WARNING.md         # ⚠️ LIES DIES ZUERST!
    └── curated-comments.json  # 135 kuratierte Testfaelle
=======
### Threat Levels

| Level | Score | Action |
|-------|-------|--------|
| CLEAN | 0-49 | Pass through |
| WARNING | 50-79 | Flag for review |
| BLOCK | 80-100 | Reject input |

### Whitelist System

Known safe content can be whitelisted with hash-chain integrity verification:

```bash
# Propose a whitelist entry
./shield.py whitelist propose --text "safe text" --exempt-from crypto_spam --reason "False positive"

# Approve (requires peer review)
./shield.py whitelist approve --seq 1 --by reviewer_name

# Verify hash chain
./shield.py whitelist verify
>>>>>>> 7e5634a (v3.1.0: Sanitize internal platform references + update README)
```

## Detection Approach

Strong precision on known injection patterns. Conservative approach: we prioritize zero false positives over catch-all detection.

What this means in practice:
- **What gets blocked is dangerous.** Every BLOCK verdict is backed by matched patterns with known malicious intent.
- **What passes through may still need other defenses.** Not everything dangerous gets caught yet -- novel attack patterns require new rules.
- **We keep improving.** The pattern database grows with real-world attack samples.

PromptShield is a filter layer. It works best as part of a layered security architecture alongside input sanitization, output validation, and access controls.

## Batch Scanning

Scan multiple inputs with duplicate detection:

```bash
# Scan a JSON file with comments/messages
./shield.py batch comments.json

# Scan all JSON files in a directory
./shield.py batch --dir /path/to/data/
```

Batch mode detects duplicate content and low-reputation patterns across inputs.

## Claude Code Integration

Use PromptShield as a pre-hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/PromptShield/prompt-shield-hook.sh"
          }
        ]
      }
    ]
  }
}
```

Every user input is scanned before reaching the AI agent. BLOCK-level threats are rejected automatically.

## Extending Patterns

Add new detection rules in `patterns.yaml`:

```yaml
your_category:
  - id: my_pattern
    regex: "(?i)suspicious\\s+pattern"
    score: 25
    description: "Description of what this catches"
```

Then validate:

```bash
<<<<<<< HEAD
./test_shield.py
# Core Tests:     29/29 passed
# Curated Tests:  73/135 passed (Layer 1 only - Layer 2a improves detection)
=======
./shield.py validate
>>>>>>> 7e5634a (v3.1.0: Sanitize internal platform references + update README)
```

## Project Structure

```
PromptShield/
├── shield.py              # Main scanner (Layer 1 + 2)
├── patterns.yaml          # Pattern database (113 patterns, 14 categories)
├── whitelist.yaml          # Hash-chain whitelist with peer review
├── prompt-shield-hook.sh  # Claude Code hook
├── test_shield.py         # Test suite
├── SCORING.md             # Detailed scoring documentation
├── LICENSE                # MIT License
└── testdata/              # Real-world attack samples (use with caution)
```

## Requirements

- **Python 3.6+**
- **PyYAML**

```bash
pip install pyyaml
```

<<<<<<< HEAD
MIT License - Frei nutzbar fuer alle KI-Agenten!
=======
No other dependencies. Single-file scanner, runs anywhere Python runs.
>>>>>>> 7e5634a (v3.1.0: Sanitize internal platform references + update README)

## Contributing

<<<<<<< HEAD
*Developed by sTLAs & RASSELBANDE AI Collective, 2026*
=======
Found a bypass? Have a new pattern to contribute? [Open an issue](https://github.com/sTLAs/PromptShield/issues) or submit a pull request.

If you're reporting a bypass, please include the input text that should have been caught and the expected threat level.

## License

[MIT License](LICENSE). Use it however you want.

## Credits

Built by [sTLAs & RASSELBANDE AI Collective](https://github.com/sTLAs).
>>>>>>> 7e5634a (v3.1.0: Sanitize internal platform references + update README)
