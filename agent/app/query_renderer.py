# query_renderer.py
"""
SOC Triage Pack - Query Renderer (agent-safe)

What this does:
- Loads a detection pack YAML
- Resolves defaults + detection-level parameters
- Safely renders SPL using {{var}} substitution (no free-form SPL generation)
- Provides a small API to list detections and render by detection_id

Designed for your current schema:
index=soc_sim, sourcetype=winsec, fields like event_code, src_ip, user, dest_host, logon_type, etc.

Install:
  pip install pyyaml
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import re
import yaml


_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


class DetectionPackError(Exception):
    pass


def _load_yaml(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"YAML not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise DetectionPackError("Detection pack YAML must be a mapping at the top level.")
    return data


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge overlay into base (dict-dict deep merge). Returns a new dict.
    """
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _resolve_placeholders_in_value(value: Any, ctx: Dict[str, Any], max_passes: int = 10) -> Any:
    """
    Resolves {{var}} placeholders in strings, and recursively in lists/dicts.
    Leaves non-strings untouched.
    """
    if isinstance(value, str):
        s = value
        for _ in range(max_passes):
            changed = False

            def repl(m: re.Match) -> str:
                nonlocal changed
                key = m.group(1)
                if key not in ctx:
                    # Leave unresolved; validator can catch missing required vars later.
                    return m.group(0)
                changed = True
                return str(ctx[key])

            s2 = _VAR_RE.sub(repl, s)
            s = s2
            if not changed:
                break
        return s

    if isinstance(value, list):
        return [_resolve_placeholders_in_value(v, ctx, max_passes=max_passes) for v in value]

    if isinstance(value, dict):
        return {k: _resolve_placeholders_in_value(v, ctx, max_passes=max_passes) for k, v in value.items()}

    return value


def _quote_spl_string(s: str) -> str:
    """
    Splunk string literal quoting for IN(...) lists.
    """
    return '"' + s.replace('"', r'\"') + '"'


def _format_for_spl(value: Any) -> str:
    """
    Formats values for insertion into SPL templates.
    - Lists -> comma-separated quoted strings (for `IN ({{vip_users}})`)
    - Strings -> as-is (caller controls quoting in template)
    - Numbers/bools -> stringified
    """
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, (int, float)) or item is None:
                parts.append(str(item))
            else:
                parts.append(_quote_spl_string(str(item)))
        return ", ".join(parts)

    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value)


def _render_spl(template: str, ctx: Dict[str, Any]) -> str:
    """
    Renders the SPL template by replacing {{var}} with formatted values.
    """
    def repl(m: re.Match) -> str:
        key = m.group(1)
        if key not in ctx:
            raise DetectionPackError(f"Missing required template variable: {key}")
        return _format_for_spl(ctx[key])

    return _VAR_RE.sub(repl, template)


@dataclass(frozen=True)
class DetectionInfo:
    id: str
    name: str
    category: str
    severity_default: str
    intent: List[str]


class QueryRenderer:
    def __init__(self, pack_yaml_path: str | Path):
        self.pack_path = Path(pack_yaml_path)
        self.pack = _load_yaml(self.pack_path)

        if "pack" not in self.pack or "detections" not in self.pack:
            raise DetectionPackError("YAML must include top-level keys: 'pack' and 'detections'.")

        if not isinstance(self.pack["detections"], list):
            raise DetectionPackError("'detections' must be a list.")

        self.pack_defaults = (self.pack.get("pack", {}) or {}).get("defaults", {}) or {}
        self._detections_by_id: Dict[str, Dict[str, Any]] = {}

        for d in self.pack["detections"]:
            if not isinstance(d, dict) or "id" not in d:
                raise DetectionPackError("Each detection must be a mapping with an 'id'.")
            did = d["id"]
            if did in self._detections_by_id:
                raise DetectionPackError(f"Duplicate detection id: {did}")
            self._detections_by_id[did] = d

    def list_detections(self) -> List[DetectionInfo]:
        out: List[DetectionInfo] = []
        for did, d in self._detections_by_id.items():
            out.append(
                DetectionInfo(
                    id=did,
                    name=d.get("name", did),
                    category=d.get("category", "unknown"),
                    severity_default=d.get("severity_default", "medium"),
                    intent=list(d.get("intent", [])) if isinstance(d.get("intent", []), list) else [],
                )
            )
        return sorted(out, key=lambda x: x.id)

    def get_detection(self, detection_id: str) -> Dict[str, Any]:
        if detection_id not in self._detections_by_id:
            raise DetectionPackError(f"Unknown detection id: {detection_id}")
        return self._detections_by_id[detection_id]

    def render(
        self,
        detection_id: str,
        overrides: Optional[Dict[str, Any]] = None,
        validate: bool = True,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Returns (rendered_spl, resolved_context).

        overrides: caller-supplied params (e.g., {"earliest":"-5m","spray_min_attempts":20})
        validate: if True, fails fast on missing template vars
        """
        d = self.get_detection(detection_id)

        # 1) Start context with pack defaults
        ctx: Dict[str, Any] = dict(self.pack_defaults)

        # 2) Merge detection parameters (may contain placeholders)
        det_params = d.get("parameters", {}) or {}
        if not isinstance(det_params, dict):
            raise DetectionPackError(f"Detection '{detection_id}' parameters must be a dict.")

        # 3) Apply user overrides (highest priority)
        overrides = overrides or {}
        if not isinstance(overrides, dict):
            raise DetectionPackError("overrides must be a dict if provided.")

        # Merge ctx <- det_params <- overrides (deep merge to support nested later)
        ctx = _deep_merge(ctx, det_params)
        ctx = _deep_merge(ctx, overrides)

        # 4) Resolve placeholder references inside ctx itself (e.g. earliest: "{{earliest}}")
        #    We do multiple passes so values can reference other values.
        ctx = _resolve_placeholders_in_value(ctx, ctx)

        # 5) Render SPL
        spl_tmpl = d.get("spl")
        if not isinstance(spl_tmpl, str) or not spl_tmpl.strip():
            raise DetectionPackError(f"Detection '{detection_id}' missing non-empty 'spl' template.")

        if validate:
            rendered = _render_spl(spl_tmpl, ctx)
        else:
            # Best-effort: leave unresolved placeholders as-is
            rendered = _resolve_placeholders_in_value(spl_tmpl, {k: _format_for_spl(v) for k, v in ctx.items()})

        # normalize whitespace a bit (optional)
        rendered = "\n".join(line.rstrip() for line in rendered.strip().splitlines())

        return rendered, ctx


if __name__ == "__main__":
    # Example usage
    renderer = QueryRenderer("detections/winsec_triage_pack.yml")

    print("Detections:")
    for info in renderer.list_detections():
        print(f"- {info.id}: {info.name} [{info.category}] ({info.severity_default})")

    spl, ctx = renderer.render(
        "auth_password_spray",
        overrides={
            "earliest": "-10m",
            "spray_distinct_users": 5,
            "spray_min_attempts": 10,
        },
    )

    print("\nRendered SPL:\n")
    print(spl)