#!/usr/bin/env python3
"""
PROMPT-SHIELD - Prompt Injection Firewall für KI-Agenten
Version: 3.2.0 | Datum: 2026-02-18

Erkennt und blockiert Prompt Injection Angriffe in Text-Input.
Mit Zwei-Pass-System: Pattern-Matching + Duplikat-Erkennung.
Whitelist v2: Hash-Chain Integritaet + Peer-Review Approval.

Usage:
    shield.py scan "text to check"
    shield.py scan --file input.txt
    shield.py --ml scan "text"             # Mit ML-Layer (optional)
    shield.py --ml auto scan "text"        # ML wenn verfuegbar, sonst Regex
    shield.py ml-download                  # ML-Modell herunterladen
    shield.py batch comments.json          # Batch-Scan mit Duplikat-Erkennung
    shield.py batch --dir /path/to/jsons   # Mehrere Dateien
    shield.py validate                     # Pattern-Datei validieren
    shield.py whitelist verify             # Hash-Chain pruefen
    shield.py whitelist list               # Aktive Eintraege
    shield.py whitelist propose --text "..." --exempt-from crypto_spam --reason "FP"
    shield.py whitelist approve --seq 1 --by reviewer2
    cat input.txt | shield.py scan --stdin
"""

import re
import sys
import json
import hashlib
import argparse
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# Pfade
SHIELD_DIR = Path(__file__).parent
PATTERN_FILE = SHIELD_DIR / "patterns.yaml"
WHITELIST_FILE = SHIELD_DIR / "whitelist.yaml"
WHITELIST_LOG = SHIELD_DIR / "whitelist-audit.log"


@dataclass
class Match:
    """Ein gefundenes Pattern-Match"""
    pattern_id: str
    category: str
    score: int
    description: str
    matched_text: str
    position: tuple


@dataclass
class ScanResult:
    """Ergebnis eines Scans"""
    threat_level: str  # CLEAN, WARNING, BLOCK
    total_score: int
    matches: List[Match] = field(default_factory=list)
    recommendation: str = ""
    sanitized_text: Optional[str] = None
    duplicate_count: int = 1
    karma: int = 0
    # ML-Felder (None wenn ML nicht aktiv)
    ml_score: Optional[int] = None
    ml_confidence: Optional[float] = None
    ml_model: Optional[str] = None


@dataclass
class BatchResult:
    """Ergebnis eines Batch-Scans"""
    total: int
    clean: int
    warning: int
    block: int
    duplicates_found: int
    low_karma_count: int
    results: List[Dict] = field(default_factory=list)


def load_patterns() -> Dict[str, Any]:
    """Lade Patterns aus YAML-Datei (keine Inline-Patterns mehr seit v3.0.3)"""
    try:
        import yaml
    except ImportError:
        print("FEHLER: PyYAML nicht installiert! pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    if not PATTERN_FILE.exists():
        print(f"FEHLER: Pattern-Datei nicht gefunden: {PATTERN_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(PATTERN_FILE) as f:
        return yaml.safe_load(f)


def normalize_text(text: str) -> str:
    """Normalisiere Text vor dem Hashing (Whitespace, Zero-Width-Chars, Unicode)."""
    import unicodedata
    text = text.strip()
    # Zero-Width-Chars entfernen (Pentest Finding)
    text = re.sub(r'[\u200b\u200c\u200d\u200e\u200f\ufeff]', '', text)
    text = re.sub(r'\s+', ' ', text)
    text = unicodedata.normalize('NFC', text)
    return text


def text_to_hash(text: str) -> str:
    """Berechne SHA256-Hash des normalisierten Textes."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def compute_entry_hash(prev_hash: str, entry: Dict) -> str:
    """Berechne den Chain-Hash eines Whitelist-Eintrags."""
    exempt = json.dumps(sorted(entry.get("exempt_from", [])))
    approved = json.dumps(sorted(entry.get("approved_by", [])))
    data = f"{prev_hash}|{entry['text_hash']}|{exempt}|{entry.get('proposed_by','')}|{approved}|{entry.get('created_at','')}|{entry.get('expires','')}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# === WHITELIST v2: Hash-Chain + Peer Review ===

_GENESIS_SEED = "GENESIS|2026-02-10|PromptShield-Whitelist-v2"
_DEFAULT_GENESIS = hashlib.sha256(_GENESIS_SEED.encode("utf-8")).hexdigest()

_WL_DEFAULTS = {
    "version": "2.0",
    "enabled": False,
    "genesis_hash": _DEFAULT_GENESIS,
    "settings": {
        "max_entries": 200,
        "max_categories_per_entry": 3,
        "require_expiry": True,
        "max_expiry_days": 180,
        "min_approvals": 2,
        "self_approve": False,
    },
    "entries": [],
}


def load_whitelist() -> Dict[str, Any]:
    """Lade Whitelist v2 aus YAML-Datei.
    Laedt IMMER die echten Daten - enabled steuert nur den Scan-Effekt,
    nicht die Verwaltungs-Befehle (list, approve, verify)."""
    try:
        import yaml
        with open(WHITELIST_FILE) as f:
            wl = yaml.safe_load(f) or {}
        # Defaults fuer fehlende Felder ergaenzen
        for key, val in _WL_DEFAULTS.items():
            if key not in wl:
                wl[key] = val
        return wl
    except (ImportError, FileNotFoundError):
        return dict(_WL_DEFAULTS)


def _save_whitelist(wl: Dict[str, Any]):
    """Speichere Whitelist v2 als YAML."""
    import yaml
    with open(WHITELIST_FILE, "w") as f:
        yaml.dump(wl, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def validate_chain(wl: Dict[str, Any]) -> List[str]:
    """Pruefe Hash-Chain Integritaet. Gibt Liste von Fehlern zurueck."""
    errors = []
    genesis = wl.get("genesis_hash", _DEFAULT_GENESIS)
    expected_prev = genesis
    settings = wl.get("settings", _WL_DEFAULTS["settings"])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for entry in wl.get("entries", []):
        seq = entry.get("seq", "?")

        # Chain-Link pruefen
        if entry.get("prev_hash") != expected_prev:
            errors.append(f"CHAIN BROKEN bei seq {seq}: prev_hash stimmt nicht!")
            return errors  # Chain ist ab hier komplett ungueltig

        # Entry-Hash verifizieren
        computed = compute_entry_hash(entry["prev_hash"], entry)
        if computed != entry.get("entry_hash"):
            errors.append(f"TAMPERED seq {seq}: entry_hash stimmt nicht! Erwartet {computed[:16]}..., gefunden {str(entry.get('entry_hash',''))[:16]}...")
            return errors

        # Self-Approval pruefen (case-insensitive)
        if not settings.get("self_approve", False):
            proposer = entry.get("proposed_by", "").upper()
            if proposer and proposer in [a.upper() for a in entry.get("approved_by", [])]:
                errors.append(f"SELF-APPROVE seq {seq}: {entry['proposed_by']} hat sich selbst approved!")

        # Approval-Count pruefen
        min_approvals = settings.get("min_approvals", 2)
        actual = len(entry.get("approved_by", []))
        if actual < min_approvals:
            errors.append(f"WARNUNG seq {seq}: Nur {actual}/{min_approvals} Approvals")

        # Kategorie-Limit pruefen
        max_cat = settings.get("max_categories_per_entry", 3)
        exempt = entry.get("exempt_from", [])
        if len(exempt) > max_cat:
            errors.append(f"WARNUNG seq {seq}: {len(exempt)} Kategorien (max {max_cat})")

        expected_prev = entry["entry_hash"]

    return errors


def get_active_entries(wl: Dict[str, Any]) -> List[Dict]:
    """Gibt nur aktive (nicht abgelaufene) Whitelist-Eintraege zurueck."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    active = []
    settings = wl.get("settings", _WL_DEFAULTS["settings"])
    min_approvals = settings.get("min_approvals", 2)

    for entry in wl.get("entries", []):
        # Abgelaufen?
        expires = entry.get("expires", "")
        if expires and expires < now:
            continue
        # Genug Approvals?
        if len(entry.get("approved_by", [])) < min_approvals:
            continue
        active.append(entry)
    return active


def is_whitelisted(text: str, whitelist: Dict[str, Any]) -> Optional[str]:
    """Pruefe ob Text gewhitelistet ist (v2: kategorie-spezifisch).
    Gibt Whitelist-Grund zurueck oder None fuer globalen Hash-Match."""
    if not whitelist.get("enabled", False):
        return None

    th = text_to_hash(text)
    for entry in get_active_entries(whitelist):
        if entry.get("text_hash") == th:
            reason = entry.get("reason", "Whitelisted")
            _audit_log(th[:16], f"MATCH seq={entry.get('seq','?')} reason={reason}")
            return reason
    return None


def get_exempt_categories(text: str, whitelist: Dict[str, Any]) -> set:
    """Gibt Set von Kategorien zurueck die fuer diesen Text exempt sind."""
    if not whitelist.get("enabled", False):
        return set()

    th = text_to_hash(text)
    exempt = set()
    for entry in get_active_entries(whitelist):
        if entry.get("text_hash") == th:
            exempt.update(entry.get("exempt_from", []))
    return exempt


def _audit_log(identifier: str, action: str):
    """Schreibe Whitelist-Nutzung ins Audit-Log (append-only)."""
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(WHITELIST_LOG, "a") as f:
            f.write(f"{ts} | {identifier} | {action}\n")
    except OSError:
        pass


def whitelist_propose(text: str, exempt_from: List[str], reason: str,
                      proposed_by: str, sample_ref: str = "") -> Dict:
    """Schlage einen neuen Whitelist-Eintrag vor (Status: pending)."""
    import yaml
    wl = load_whitelist()
    settings = wl.get("settings", _WL_DEFAULTS["settings"])

    # Limits pruefen
    max_entries = settings.get("max_entries", 200)
    if len(wl.get("entries", [])) >= max_entries:
        return {"error": f"Max {max_entries} Eintraege erreicht!"}

    max_cat = settings.get("max_categories_per_entry", 3)
    if len(exempt_from) > max_cat:
        return {"error": f"Max {max_cat} Kategorien pro Eintrag!"}

    max_days = settings.get("max_expiry_days", 180)
    expires = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(days=max_days)).strftime("%Y-%m-%d")

    # Neuen Eintrag bauen
    entries = wl.get("entries", [])
    seq = (entries[-1]["seq"] + 1) if entries else 1
    prev_hash = entries[-1]["entry_hash"] if entries else wl.get("genesis_hash", _DEFAULT_GENESIS)

    th = text_to_hash(text)
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    entry = {
        "seq": seq,
        "prev_hash": prev_hash,
        "text_hash": th,
        "reason": reason,
        "exempt_from": sorted(exempt_from),
        "proposed_by": proposed_by,
        "approved_by": [],
        "created_at": created_at,
        "expires": expires,
        "sample_ref": sample_ref,
    }
    entry["entry_hash"] = compute_entry_hash(prev_hash, entry)

    entries.append(entry)
    wl["entries"] = entries

    # Whitelist noch nicht aktivieren (braucht Approvals)
    _save_whitelist(wl)
    _audit_log(th[:16], f"PROPOSE seq={seq} by={proposed_by} exempt={exempt_from}")

    return {"ok": True, "seq": seq, "text_hash": th, "expires": expires,
            "approvals_needed": settings.get("min_approvals", 2)}


def whitelist_approve(seq: int, approved_by: str) -> Dict:
    """Approve einen Whitelist-Eintrag (Peer Review)."""
    import yaml
    wl = load_whitelist()
    settings = wl.get("settings", _WL_DEFAULTS["settings"])

    for entry in wl.get("entries", []):
        if entry.get("seq") == seq:
            # Self-Approve pruefen (case-insensitive)
            if not settings.get("self_approve", False):
                if entry.get("proposed_by", "").upper() == approved_by.upper():
                    return {"error": f"Self-Approve verboten! {approved_by} hat diesen Eintrag vorgeschlagen."}

            # Doppelt-Approve pruefen (case-insensitive)
            if approved_by.upper() in [a.upper() for a in entry.get("approved_by", [])]:
                return {"error": f"{approved_by} hat bereits approved!"}

            entry["approved_by"].append(approved_by)

            # Chain muss neu berechnet werden (approved_by hat sich geaendert)
            # Alle nachfolgenden Entry-Hashes aktualisieren
            _recompute_chain_from(wl, seq)

            _save_whitelist(wl)
            _audit_log(entry.get("text_hash", "")[:16],
                      f"APPROVE seq={seq} by={approved_by} total={len(entry['approved_by'])}")

            min_req = settings.get("min_approvals", 2)
            remaining = max(0, min_req - len(entry["approved_by"]))
            return {"ok": True, "seq": seq, "approved_by": entry["approved_by"],
                    "remaining": remaining,
                    "active": remaining == 0}

    return {"error": f"Eintrag seq={seq} nicht gefunden!"}


def _recompute_chain_from(wl: Dict, from_seq: int):
    """Berechne Hash-Chain ab einem bestimmten seq neu."""
    entries = wl.get("entries", [])
    genesis = wl.get("genesis_hash", _DEFAULT_GENESIS)

    for i, entry in enumerate(entries):
        if entry["seq"] >= from_seq:
            prev_hash = entries[i-1]["entry_hash"] if i > 0 else genesis
            entry["prev_hash"] = prev_hash
            entry["entry_hash"] = compute_entry_hash(prev_hash, entry)


def whitelist_list_active(wl: Dict[str, Any]) -> List[Dict]:
    """Liste aktive Eintraege mit Status."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    settings = wl.get("settings", _WL_DEFAULTS["settings"])
    min_approvals = settings.get("min_approvals", 2)
    result = []

    for entry in wl.get("entries", []):
        expires = entry.get("expires", "")
        expired = bool(expires and expires < now)
        approved = len(entry.get("approved_by", [])) >= min_approvals
        status = "EXPIRED" if expired else ("ACTIVE" if approved else "PENDING")

        result.append({
            "seq": entry.get("seq"),
            "status": status,
            "text_hash": entry.get("text_hash", "")[:16] + "...",
            "exempt_from": entry.get("exempt_from", []),
            "reason": entry.get("reason", ""),
            "proposed_by": entry.get("proposed_by", ""),
            "approved_by": entry.get("approved_by", []),
            "expires": expires,
        })
    return result


def validate_patterns(patterns: Dict[str, Any]) -> List[str]:
    """Validiere Pattern-Datei. Gibt Liste von Fehlern/Warnungen zurueck."""
    errors = []
    seen_ids = set()
    required_fields = {"id", "regex", "score", "description"}
    meta_keys = {"version", "last_updated", "thresholds"}

    # Thresholds pruefen
    thresholds = patterns.get("thresholds")
    if not thresholds:
        errors.append("FEHLER: 'thresholds' fehlt in patterns.yaml")
    elif not isinstance(thresholds, dict):
        errors.append("FEHLER: 'thresholds' muss ein Dict sein")
    else:
        for key in ("clean", "warning", "block"):
            if key not in thresholds:
                errors.append(f"FEHLER: thresholds.{key} fehlt")
            elif not isinstance(thresholds[key], int):
                errors.append(f"FEHLER: thresholds.{key} muss eine Zahl sein")
        if thresholds.get("clean", 0) >= thresholds.get("warning", 0):
            errors.append("FEHLER: thresholds.clean muss kleiner als thresholds.warning sein")
        if thresholds.get("warning", 0) >= thresholds.get("block", 0):
            errors.append("FEHLER: thresholds.warning muss kleiner als thresholds.block sein")

    # Kategorien pruefen
    category_count = 0
    for category, pattern_list in patterns.items():
        if category in meta_keys:
            continue

        if not isinstance(pattern_list, list):
            errors.append(f"WARNUNG: '{category}' ist keine Liste (Typ: {type(pattern_list).__name__})")
            continue

        category_count += 1
        for i, pattern in enumerate(pattern_list):
            if not isinstance(pattern, dict):
                errors.append(f"FEHLER: {category}[{i}] ist kein Dict")
                continue

            # Pflichtfelder
            missing = required_fields - set(pattern.keys())
            if missing:
                errors.append(f"FEHLER: {category}/{pattern.get('id', f'[{i}]')}: Felder fehlen: {missing}")
                continue

            pid = pattern["id"]

            # Duplikat-Check
            if pid in seen_ids:
                errors.append(f"FEHLER: Pattern-ID '{pid}' ist doppelt!")
            seen_ids.add(pid)

            # Score-Bereich
            score = pattern.get("score", 0)
            if not isinstance(score, int) or score < 1 or score > 100:
                errors.append(f"WARNUNG: {category}/{pid}: Score {score} ausserhalb 1-100")

            # Regex-Validierung
            regex = pattern.get("regex", "")
            try:
                re.compile(regex)
            except re.error as e:
                errors.append(f"FEHLER: {category}/{pid}: Ungueltige Regex: {e}")

    if category_count == 0:
        errors.append("FEHLER: Keine Pattern-Kategorien gefunden!")

    return errors


def _detect_code_fences(text: str) -> List[tuple]:
    """Finde Code-Fence-Bereiche (```...``` und `...`).
    Returns: Liste von (start, end) Tupeln."""
    fences = []
    for m in re.finditer(r'```[\s\S]*?```|`[^`\n]+`', text):
        fences.append((m.start(), m.end()))
    return fences


def _in_code_fence(pos: int, fences: List[tuple]) -> bool:
    """Pruefe ob Position innerhalb eines Code-Fence liegt."""
    return any(start <= pos < end for start, end in fences)


def _detect_educational_context(text: str) -> bool:
    """Erkennt ob Text in einem edukativen/diskutierenden Kontext steht.
    Z.B. Security-Tutorials, Beispiel-Diskussionen, Reviews."""
    markers = [
        r'(?i)\b(?:example|beispiel|here\s+is|hier\s+ist)\s+(?:of|fuer|eines?|a|an)',
        r'(?i)\b(?:for\s+instance|for\s+example|zum\s+beispiel)',
        r'(?i)\b(?:tutorial|erklaer|explain|how\s+to\s+detect|how\s+to\s+recognize)',
        r'(?i)\b(?:this\s+is\s+what|so\s+sieht|looks?\s+like\s+this)',
        r'(?i)\b(?:sample|demonstration|demo)\b',
        r'(?i)\b(?:common\s+(?:attack|pattern|technique)|typisch(?:er?|es?)\s+(?:angriff|muster))',
    ]
    count = sum(1 for m in markers if re.search(m, text))
    return count >= 2  # Mindestens 2 Marker fuer Educational-Kontext


# === Confusables: Unicode-Lookalikes normalisieren ===
_CONFUSABLES = {
    # Cyrillic -> Latin
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u04bb': 'h', '\u0455': 's', '\u0457': 'i',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K',
    '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
    # Greek -> Latin
    '\u03b1': 'a', '\u03b5': 'e', '\u03b9': 'i', '\u03bf': 'o',
    '\u03c1': 'p', '\u03c5': 'u', '\u0391': 'A', '\u0392': 'B',
    '\u0395': 'E', '\u0397': 'H', '\u0399': 'I', '\u039a': 'K',
    '\u039c': 'M', '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P',
    '\u03a4': 'T', '\u03a5': 'Y', '\u03a7': 'X', '\u0396': 'Z',
    # Math/Fullwidth -> Latin
    '\uff21': 'A', '\uff22': 'B', '\uff23': 'C', '\uff24': 'D',
    '\uff25': 'E', '\uff26': 'F', '\uff41': 'a', '\uff42': 'b',
    '\uff43': 'c', '\uff44': 'd', '\uff45': 'e', '\uff46': 'f',
}


def _normalize_confusables(text: str) -> str:
    """Ersetze Unicode-Lookalikes durch ihre Latin-Aequivalente."""
    return ''.join(_CONFUSABLES.get(c, c) for c in text)


def _decode_chain(text: str, max_depth: int = 3) -> str:
    """Rekursiv decodieren: Base64, URL-Encoding, Hex-Escapes.
    Max 3 Stufen tief um Performance zu schuetzen."""
    import base64
    from urllib.parse import unquote

    for _ in range(max_depth):
        decoded = text
        # Try Base64
        try:
            # Nur wenn es wie Base64 aussieht (mind. 20 Zeichen, passende Zeichenmenge)
            stripped = text.strip()
            if len(stripped) >= 20 and re.match(r'^[A-Za-z0-9+/=\s]+$', stripped):
                candidate = base64.b64decode(stripped, validate=True).decode('utf-8', errors='strict')
                if candidate.isprintable() and len(candidate) > 10:
                    decoded = candidate
        except Exception:
            pass
        # Try URL-Decode
        if decoded == text:
            try:
                candidate = unquote(text)
                if candidate != text:
                    decoded = candidate
            except Exception:
                pass
        # Try Hex-Escapes (\x41\x42 -> AB)
        if decoded == text:
            try:
                candidate = re.sub(
                    r'\\x([0-9a-fA-F]{2})',
                    lambda m: chr(int(m.group(1), 16)),
                    text
                )
                if candidate != text:
                    decoded = candidate
            except Exception:
                pass
        if decoded == text:
            break  # Nichts mehr zu decodieren
        text = decoded
    return text


def scan_text(text: str, patterns: Dict[str, Any],
              whitelist: Optional[Dict[str, Any]] = None) -> ScanResult:
    """Scanne Text auf Prompt Injection Patterns.

    Features:
    - Code-Fence-Awareness: Patterns in ``` Bloecken werden um 50% reduziert
    - Educational-Context: Tutorials/Beispiele erhalten Score-Reduktion
    - Confusables: Unicode-Lookalikes (Cyrillic/Greek) werden normalisiert
    - Encoding-Chain: Base64/URL/Hex werden rekursiv decodiert
    """
    # Whitelist-Check: kategorie-spezifische Exemptions
    exempt_categories = set()
    if whitelist and whitelist.get("enabled", False):
        exempt_categories = get_exempt_categories(text, whitelist)

    # Pre-Processing: Confusables normalisieren + Encoding-Chain decodieren
    scan_text_normalized = _normalize_confusables(text)
    scan_text_decoded = _decode_chain(scan_text_normalized)
    # Scanne sowohl Original als auch decodierten Text
    texts_to_scan = [text]
    if scan_text_decoded != text:
        texts_to_scan.append(scan_text_decoded)

    # Code-Fence-Erkennung
    code_fences = _detect_code_fences(text)

    # Educational-Context-Erkennung
    is_educational = _detect_educational_context(text)

    matches = []
    total_score = 0
    category_hits = {}  # Fuer Combo-Detection

    # Durchlaufe alle Pattern-Kategorien
    for category, pattern_list in patterns.items():
        if category in ("version", "last_updated", "thresholds"):
            continue

        if not isinstance(pattern_list, list):
            continue

        # Kategorie exempt? -> komplett ueberspringen
        if category in exempt_categories:
            continue

        for pattern in pattern_list:
            if not isinstance(pattern, dict):
                continue

            pid = pattern.get("id", "")

            regex = pattern.get("regex", "")
            if not regex:
                continue

            try:
                for scan_input in texts_to_scan:
                    for match in re.finditer(regex, scan_input):
                        score = pattern.get("score", 10)
                        max_matches = pattern.get("max_matches", 99)

                        # Begrenze Score bei max_matches
                        existing = len([m for m in matches if m.pattern_id == pid])
                        if existing >= max_matches:
                            continue

                        # Code-Fence-Awareness: Score halbieren fuer Matches in Fences
                        if _in_code_fence(match.start(), code_fences):
                            score = max(1, score // 2)

                        # Educational-Context: Score um 30% reduzieren
                        if is_educational:
                            score = max(1, int(score * 0.7))

                        matches.append(Match(
                            pattern_id=pid,
                            category=category,
                            score=score,
                            description=pattern.get("description", ""),
                            matched_text=match.group()[:50],
                            position=(match.start(), match.end())
                        ))
                        total_score += score
                        # Track category hits fuer Combo-Detection
                        category_hits[category] = category_hits.get(category, 0) + 1
            except re.error:
                pass  # Ungueltige Regex ignorieren

    # === PHASE 2: Heuristic Combo-Detection ===
    # Gefährliche Kombinationen erhöhen den Score
    combo_bonus = 0

    # Combo 1: Authority + Fear + Command = sehr gefährlich
    if category_hits.get("fake_authority", 0) > 0 and \
       category_hits.get("fear_triggers", 0) > 0 and \
       category_hits.get("command_injection", 0) > 0:
        combo_bonus += 20

    # Combo 2: Authority + Command (ohne Fear) = gefährlich
    elif category_hits.get("fake_authority", 0) > 0 and \
         category_hits.get("command_injection", 0) > 0:
        combo_bonus += 10

    # Combo 3: Crypto + Link = Spam-Bot
    if category_hits.get("crypto_spam", 0) > 0 and \
       category_hits.get("link_spam", 0) > 0:
        combo_bonus += 25

    # Combo 4: Fake Engagement + Link = Marketing Spam
    if category_hits.get("fake_engagement", 0) > 0 and \
       category_hits.get("link_spam", 0) > 0:
        combo_bonus += 20

    # Combo 5: Viele Kategorien getroffen = verdächtig
    if len(category_hits) >= 4:
        combo_bonus += 15
    elif len(category_hits) >= 3:
        combo_bonus += 10

    total_score += combo_bonus

    # Bestimme Threat-Level
    thresholds = patterns.get("thresholds", {"clean": 49, "warning": 79, "block": 80})
    if total_score <= thresholds["clean"]:
        threat_level = "CLEAN"
        recommendation = "Text ist sicher"
    elif total_score <= thresholds["warning"]:
        threat_level = "WARNING"
        recommendation = "Vorsicht - mögliche Manipulation erkannt"
    else:
        threat_level = "BLOCK"
        recommendation = "BLOCKIEREN - Prompt Injection erkannt!"

    # Sanitize Text bei WARNING oder BLOCK
    sanitized = None
    if threat_level in ("WARNING", "BLOCK"):
        sanitized = sanitize_text(text, matches)

    return ScanResult(
        threat_level=threat_level,
        total_score=min(total_score, 100),  # Cap bei 100
        matches=matches,
        recommendation=recommendation,
        sanitized_text=sanitized
    )


def scan_with_ml(text: str, patterns: Dict[str, Any],
                 ml_detector, whitelist: Optional[Dict[str, Any]] = None) -> ScanResult:
    """Scan mit Regex + ML combined Scoring.

    Score-Kombination: final_score = max(regex_score, int(ml_confidence * 100))
    ML kann nur erhoehen, nie unterdruecken.
    """
    # Regex-Scan zuerst
    result = scan_text(text, patterns, whitelist=whitelist)
    regex_score = result.total_score

    # ML-Inference
    try:
        ml_confidence, ml_label = ml_detector.predict(text)
        ml_score_int = int(ml_confidence * 100)
    except Exception as e:
        # ML fehlgeschlagen - Fallback auf Regex, mit Warnung
        print(f"WARNING: ML inference failed: {e}", file=sys.stderr)
        return result

    # Kombinieren: Maximum von Regex und ML
    final_score = max(regex_score, ml_score_int)
    final_score = min(final_score, 100)

    # Re-klassifizieren mit kombiniertem Score
    thresholds = patterns.get("thresholds", {"clean": 49, "warning": 79, "block": 80})
    if final_score <= thresholds["clean"]:
        threat_level = "CLEAN"
        recommendation = "Text ist sicher"
    elif final_score <= thresholds["warning"]:
        threat_level = "WARNING"
        recommendation = "Vorsicht - moegliche Manipulation erkannt"
    else:
        threat_level = "BLOCK"
        recommendation = "BLOCKIEREN - Prompt Injection erkannt!"

    # Sanitize wenn noetig
    sanitized = result.sanitized_text
    if threat_level in ("WARNING", "BLOCK") and not sanitized:
        sanitized = sanitize_text(text, result.matches)

    return ScanResult(
        threat_level=threat_level,
        total_score=final_score,
        matches=result.matches,
        recommendation=recommendation,
        sanitized_text=sanitized,
        ml_score=ml_score_int,
        ml_confidence=round(ml_confidence, 4),
        ml_model=ml_detector.model_name
    )


def scan_with_context(text: str, patterns: Dict[str, Any],
                      duplicate_count: int = 1, karma: int = 0,
                      whitelist: Optional[Dict[str, Any]] = None) -> ScanResult:
    """Scan mit Kontext-Informationen (Duplikate, Karma)"""
    # Basis-Scan (mit Whitelist)
    result = scan_text(text, patterns, whitelist=whitelist)
    if result.recommendation.startswith("Whitelisted:"):
        return result  # Whitelisted -> sofort zurueck
    base_score = result.total_score

    # === PASS 2: Duplikat-Bonus (v2.1 - recalibriert nach FP-Report) ===
    # Duplikate allein duerfen nie BLOCK ausloesen - nur in Kombination mit Pattern-Hits
    dup_bonus = 0
    if duplicate_count >= 5:
        dup_bonus = 25  # 5+ Duplikate = deutlich verdaechtig
    elif duplicate_count >= 3:
        dup_bonus = 20  # 3+ Duplikate = verdaechtig
    elif duplicate_count == 2:
        dup_bonus = 10  # 2 Duplikate = leicht verdaechtig

    # === Karma-Malus: Keine Upvotes = verdächtig ===
    karma_malus = 0
    if karma <= 0:
        karma_malus = 10  # Keine Upvotes = leicht verdaechtig
    elif karma < 3:
        karma_malus = 5   # Wenig Upvotes = minimal

    # Behavioral Score (dup + karma) ohne Pattern-Match: max 50 (nie BLOCK!)
    behavioral_score = dup_bonus + karma_malus
    if base_score == 0:
        behavioral_score = min(behavioral_score, 45)  # Ohne Pattern-Match: max WARNING

    # Neuer Gesamt-Score
    total_score = min(base_score + behavioral_score, 100)

    # Neu klassifizieren
    thresholds = patterns.get("thresholds", {"clean": 49, "warning": 79, "block": 80})
    if total_score <= thresholds["clean"]:
        threat_level = "CLEAN"
        recommendation = "Text ist sicher"
    elif total_score <= thresholds["warning"]:
        threat_level = "WARNING"
        recommendation = "Vorsicht - mögliche Manipulation"
    else:
        threat_level = "BLOCK"
        recommendation = "BLOCKIEREN - Spam/Injection erkannt!"

    return ScanResult(
        threat_level=threat_level,
        total_score=total_score,
        matches=result.matches,
        recommendation=recommendation,
        sanitized_text=result.sanitized_text if threat_level != "CLEAN" else None,
        duplicate_count=duplicate_count,
        karma=karma
    )


def scan_batch(files: List[Path], patterns: Dict[str, Any],
               whitelist: Optional[Dict[str, Any]] = None,
               ml_detector=None) -> BatchResult:
    """Batch-Scan mit Duplikat-Erkennung über mehrere Dateien"""
    from collections import Counter

    # Pass 1: Sammle alle Kommentare und zähle Duplikate
    all_comments = []  # (text, karma, source_file)

    for fpath in files:
        try:
            with open(fpath) as f:
                data = json.load(f)
            for c in data.get("comments", []):
                text = c.get("content", "").strip()
                if text:
                    # Karma aus Author-Daten oder Votes
                    karma = c.get("author", {}).get("karma", 0)
                    if karma == 0:
                        karma = c.get("votes", c.get("upvotes", 0))
                    all_comments.append((text, karma, fpath.name))
        except (json.JSONDecodeError, FileNotFoundError):
            continue

    # Duplikat-Zählung
    text_counts = Counter(text for text, _, _ in all_comments)

    # Pass 2: Scan mit Kontext
    results = []
    clean = warning = block = 0
    low_karma = 0

    for text, karma, source in all_comments:
        dup_count = text_counts.get(text, 1)
        result = scan_with_context(text, patterns, dup_count, karma, whitelist=whitelist)

        # ML-Boost wenn verfuegbar
        if ml_detector:
            try:
                ml_conf, _ = ml_detector.predict(text)
                ml_score_int = int(ml_conf * 100)
                if ml_score_int > result.total_score:
                    combined = min(ml_score_int, 100)
                    thresholds = patterns.get("thresholds",
                                              {"clean": 49, "warning": 79, "block": 80})
                    if combined <= thresholds["clean"]:
                        tl, rec = "CLEAN", "Text ist sicher"
                    elif combined <= thresholds["warning"]:
                        tl, rec = "WARNING", "Vorsicht - moegliche Manipulation"
                    else:
                        tl, rec = "BLOCK", "BLOCKIEREN - Prompt Injection erkannt!"
                    result = ScanResult(
                        threat_level=tl, total_score=combined,
                        matches=result.matches, recommendation=rec,
                        sanitized_text=result.sanitized_text,
                        duplicate_count=dup_count, karma=karma,
                        ml_score=ml_score_int,
                        ml_confidence=round(ml_conf, 4),
                        ml_model=ml_detector.model_name
                    )
            except Exception:
                pass  # ML-Fehler in Batch: leise weiter mit Regex

        if result.threat_level == "CLEAN":
            clean += 1
        elif result.threat_level == "WARNING":
            warning += 1
        else:
            block += 1

        if karma <= 0:
            low_karma += 1

        results.append({
            "text": text[:100],
            "threat_level": result.threat_level,
            "score": result.total_score,
            "duplicate_count": dup_count,
            "karma": karma,
            "source": source
        })

    duplicates_found = sum(1 for cnt in text_counts.values() if cnt > 1)

    return BatchResult(
        total=len(all_comments),
        clean=clean,
        warning=warning,
        block=block,
        duplicates_found=duplicates_found,
        low_karma_count=low_karma,
        results=results
    )


def sanitize_text(text: str, matches: List[Match]) -> str:
    """Entferne/markiere gefährliche Teile"""
    result = text

    # Sortiere Matches nach Position (rückwärts, damit Indizes stimmen)
    sorted_matches = sorted(matches, key=lambda m: m.position[0], reverse=True)

    for match in sorted_matches:
        start, end = match.position
        if match.score >= 30:
            # Ersetze mit Warnung
            result = result[:start] + f"[⚠️ BLOCKED: {match.description}]" + result[end:]
        elif match.score >= 20:
            # Markiere
            result = result[:start] + f"[⚠️ {result[start:end]}]" + result[end:]

    return result


def format_console_output(result: ScanResult) -> str:
    """Formatiere Ausgabe für Konsole"""
    # Farben
    colors = {
        "CLEAN": "\033[92m",   # Grün
        "WARNING": "\033[93m", # Gelb
        "BLOCK": "\033[91m",   # Rot
        "RESET": "\033[0m"
    }

    c = colors.get(result.threat_level, "")
    r = colors["RESET"]

    lines = [
        f"\n{'='*50}",
        f"PROMPT-SHIELD Scan Result",
        f"{'='*50}",
        f"Threat Level: {c}{result.threat_level}{r}",
        f"Score: {result.total_score}/100",
    ]

    if result.ml_score is not None:
        lines.append(f"ML Score: {result.ml_score}/100 (confidence: {result.ml_confidence:.2%})")
        lines.append(f"ML Model: {result.ml_model}")

    lines.append(f"Recommendation: {result.recommendation}")

    if result.matches:
        lines.append(f"\nPatterns gefunden ({len(result.matches)}):")
        for m in result.matches[:10]:  # Max 10 anzeigen
            lines.append(f"  [{m.score:2d}] {m.category}/{m.pattern_id}: {m.description}")
            lines.append(f"       Match: \"{m.matched_text}\"")

    if result.sanitized_text and result.threat_level != "CLEAN":
        lines.append(f"\nSanitized Text:")
        lines.append(f"  {result.sanitized_text[:200]}...")

    lines.append(f"{'='*50}\n")

    return "\n".join(lines)


def format_json_output(result: ScanResult) -> str:
    """Formatiere Ausgabe als JSON"""
    output = {
        "threat_level": result.threat_level,
        "score": result.total_score,
        "recommendation": result.recommendation,
        "patterns_found": [
            {
                "id": m.pattern_id,
                "category": m.category,
                "score": m.score,
                "description": m.description,
                "match": m.matched_text
            }
            for m in result.matches
        ],
        "sanitized_text": result.sanitized_text
    }
    # ML-Felder nur wenn ML aktiv war
    if result.ml_score is not None:
        output["ml_score"] = result.ml_score
        output["ml_confidence"] = result.ml_confidence
        output["ml_model"] = result.ml_model
    return json.dumps(output, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(
        description="PROMPT-SHIELD v3.2.0 - Prompt Injection Firewall"
    )
    parser.add_argument("command", nargs="?", default="scan",
                        help="Befehl: scan, batch, validate, whitelist, ml-download, version")
    parser.add_argument("text", nargs="?", help="Text/Subcommand (scan: Text, batch: Datei, whitelist: verify|list|propose|approve)")
    parser.add_argument("--file", "-f", help="Datei zum Scannen")
    parser.add_argument("--dir", "-d", help="Verzeichnis mit JSON-Dateien (fuer batch)")
    parser.add_argument("--stdin", action="store_true", help="Lese von stdin")
    parser.add_argument("--json", "-j", action="store_true", help="JSON-Output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Nur Exit-Code")
    parser.add_argument("--no-whitelist", action="store_true", help="Whitelist deaktivieren")
    # ML-Layer (optional)
    parser.add_argument("--ml", nargs="?", const="on", default=None,
                        choices=["on", "auto"],
                        help="ML-Layer: 'on' (erzwingen), 'auto' (wenn verfuegbar)")
    # Whitelist-spezifische Argumente
    parser.add_argument("--exempt-from", help="Kategorien (komma-separiert)")
    parser.add_argument("--reason", help="Grund fuer Whitelist-Eintrag")
    parser.add_argument("--by", help="Container-Name (fuer propose/approve)")
    parser.add_argument("--seq", type=int, help="Sequenz-Nummer (fuer approve)")
    parser.add_argument("--sample-ref", default="", help="Referenz zum Sample")

    args = parser.parse_args()

    if args.command == "version":
        print("PROMPT-SHIELD v3.2.0")
        return 0

    # === ML-DOWNLOAD COMMAND ===
    if args.command == "ml-download":
        try:
            from shield_ml import MLDetector
            detector = MLDetector()
            if not detector.is_available:
                print("FEHLER: ML-Dependencies fehlen!", file=sys.stderr)
                print("  pip install -r requirements-ml.txt", file=sys.stderr)
                return 1
            print(f"Lade ML-Modell: {detector.model_name}")
            print(f"  Ziel: {detector.model_dir}")
            if detector.ensure_model():
                # Teste Laden
                if detector.load():
                    print(f"  Modell geladen und einsatzbereit!")
                    return 0
                else:
                    print(f"FEHLER: {detector.load_error}", file=sys.stderr)
                    return 1
            else:
                print(f"FEHLER: {detector.load_error}", file=sys.stderr)
                return 1
        except ImportError:
            print("FEHLER: shield_ml.py nicht gefunden!", file=sys.stderr)
            return 1

    patterns = load_patterns()

    # === ML LAYER (optional) ===
    ml_detector = None
    ml_enabled = False
    if args.ml is not None:
        try:
            from shield_ml import MLDetector
            ml_detector = MLDetector()
            if args.ml == "on":
                if not ml_detector.is_available:
                    print("FEHLER: ML-Dependencies fehlen!", file=sys.stderr)
                    print("  pip install -r requirements-ml.txt", file=sys.stderr)
                    return 1
                if not ml_detector.load():
                    print(f"FEHLER: {ml_detector.load_error}", file=sys.stderr)
                    return 1
                ml_enabled = True
            elif args.ml == "auto":
                if ml_detector.is_available and ml_detector.load():
                    ml_enabled = True
                else:
                    ml_detector = None
        except ImportError:
            if args.ml == "on":
                print("FEHLER: shield_ml.py nicht gefunden!", file=sys.stderr)
                return 1
            # auto: leise weiter ohne ML

    # === VALIDATE MODUS ===
    if args.command == "validate":
        errors = validate_patterns(patterns)
        if errors:
            print(f"Pattern-Validierung: {len(errors)} Problem(e) gefunden:\n")
            for e in errors:
                print(f"  {e}")
            return 1
        else:
            cat_count = sum(1 for k, v in patterns.items()
                          if k not in ("version", "last_updated", "thresholds")
                          and isinstance(v, list))
            pat_count = sum(len(v) for k, v in patterns.items()
                          if k not in ("version", "last_updated", "thresholds")
                          and isinstance(v, list))
            print(f"Pattern-Validierung OK: {cat_count} Kategorien, {pat_count} Patterns, 0 Fehler")
            return 0

    # === WHITELIST MODUS ===
    if args.command == "whitelist":
        subcmd = args.text or "list"

        if subcmd == "verify":
            wl = load_whitelist()
            errors = validate_chain(wl)
            total = len(wl.get("entries", []))
            active = len(get_active_entries(wl))
            if errors:
                print(f"CHAIN FEHLER ({len(errors)}):")
                for e in errors:
                    print(f"  {e}")
                return 1
            else:
                print(f"Chain valid: {total} Eintraege, {active} aktiv, {total - active} pending/expired")
                return 0

        elif subcmd == "list":
            wl = load_whitelist()
            entries = whitelist_list_active(wl)
            if not entries:
                print("Keine Whitelist-Eintraege.")
                return 0
            if args.json:
                print(json.dumps(entries, indent=2, ensure_ascii=False))
            else:
                for e in entries:
                    status_sym = {"ACTIVE": "+", "PENDING": "?", "EXPIRED": "x"}.get(e["status"], " ")
                    cats = ",".join(e["exempt_from"])
                    approvals = ",".join(e["approved_by"]) or "-"
                    print(f"  [{status_sym}] seq={e['seq']} hash={e['text_hash']} exempt={cats} by={e['proposed_by']} approved={approvals} expires={e['expires']}")
                    print(f"      reason: {e['reason']}")
            return 0

        elif subcmd == "propose":
            if not args.text or args.text == "propose":
                # Text von --file oder stdin
                if args.file:
                    text = Path(args.file).read_text().strip()
                elif args.stdin:
                    text = sys.stdin.read().strip()
                else:
                    print("FEHLER: Text noetig! Nutze --file oder --stdin")
                    return 1
            exempt = [c.strip() for c in (args.exempt_from or "").split(",") if c.strip()]
            if not exempt:
                print("FEHLER: --exempt-from noetig (z.B. --exempt-from crypto_spam)")
                return 1
            reason = args.reason or "Kein Grund angegeben"
            by = args.by or "UNKNOWN"
            result = whitelist_propose(text, exempt, reason, by, args.sample_ref)
            if "error" in result:
                print(f"FEHLER: {result['error']}")
                return 1
            print(f"Vorschlag erstellt: seq={result['seq']} hash={result['text_hash'][:16]}...")
            print(f"  Braucht noch {result['approvals_needed']} Approvals")
            print(f"  Laeuft ab: {result['expires']}")
            return 0

        elif subcmd == "approve":
            if not args.seq:
                print("FEHLER: --seq noetig")
                return 1
            by = args.by or "UNKNOWN"
            result = whitelist_approve(args.seq, by)
            if "error" in result:
                print(f"FEHLER: {result['error']}")
                return 1
            status = "AKTIV" if result["active"] else f"noch {result['remaining']} Approvals noetig"
            print(f"Approved: seq={result['seq']} ({status})")
            print(f"  Approved by: {', '.join(result['approved_by'])}")
            return 0

        else:
            print(f"Unbekannter Whitelist-Befehl: {subcmd}")
            print("Verfuegbar: verify, list, propose, approve")
            return 1

    # Whitelist laden (wenn nicht deaktiviert)
    whitelist = None if args.no_whitelist else load_whitelist()

    # === BATCH MODUS ===
    if args.command == "batch":
        import glob

        files = []
        if args.dir:
            files = [Path(f) for f in glob.glob(f"{args.dir}/*.json")]
        elif args.text:
            # Kann ein Glob-Pattern oder eine Datei sein
            if "*" in args.text:
                files = [Path(f) for f in glob.glob(args.text)]
            else:
                files = [Path(args.text)]

        if not files:
            print("Keine JSON-Dateien gefunden!")
            return 1

        result = scan_batch(files, patterns, whitelist=whitelist,
                            ml_detector=ml_detector if ml_enabled else None)

        if args.json:
            print(json.dumps({
                "total": result.total,
                "clean": result.clean,
                "warning": result.warning,
                "block": result.block,
                "duplicates_found": result.duplicates_found,
                "low_karma_count": result.low_karma_count,
                "detection_rate": f"{100*(result.warning+result.block)//result.total}%",
                "results": result.results[:20]  # Top 20
            }, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'='*60}")
            print(f"PROMPT-SHIELD v2.0 - Batch Scan")
            print(f"{'='*60}")
            print(f"Dateien gescannt: {len(files)}")
            print(f"Total Kommentare: {result.total}")
            print(f"Duplikate gefunden: {result.duplicates_found}")
            print(f"Ohne Karma/Upvotes: {result.low_karma_count}")
            print()
            print(f"  🟢 CLEAN:   {result.clean} ({100*result.clean//result.total}%)")
            print(f"  🟡 WARNING: {result.warning} ({100*result.warning//result.total}%)")
            print(f"  🔴 BLOCK:   {result.block} ({100*result.block//result.total}%)")
            print()
            rate = 100*(result.warning+result.block)//result.total
            print(f"📊 ERKENNUNGSRATE: {rate}%")
            print(f"{'='*60}\n")

        return 0 if result.block == 0 else 2

    # === SINGLE SCAN MODUS ===
    # Text ermitteln
    if args.stdin:
        text = sys.stdin.read()
    elif args.file:
        text = Path(args.file).read_text()
    elif args.text:
        text = args.text
    else:
        parser.print_help()
        return 1

    # Scan durchführen (mit oder ohne ML)
    if ml_enabled and ml_detector:
        result = scan_with_ml(text, patterns, ml_detector, whitelist=whitelist)
    else:
        result = scan_text(text, patterns, whitelist=whitelist)

    # Ausgabe
    if args.quiet:
        pass  # Nur Exit-Code
    elif args.json:
        print(format_json_output(result))
    else:
        print(format_console_output(result))

    # Exit-Code
    if result.threat_level == "CLEAN":
        return 0
    elif result.threat_level == "WARNING":
        return 1
    else:  # BLOCK
        return 2


if __name__ == "__main__":
    sys.exit(main())
