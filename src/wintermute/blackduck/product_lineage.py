from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from wintermute.blackduck.lineage import (
    build_project_version_indexes,
    discover_lineage_contexts,
)
from wintermute.blackduck.models import LineageContext, ProjectVersionRef


class ProductLineageCache:
    def __init__(self, path, client, inventory, *, resolve_bom_names, refresh=False):
        self.path = Path(path)
        self.client = client
        self.resolve_bom_names = resolve_bom_names
        refs = [item.project_version for item in inventory.items]
        self.by_href, self.by_name = build_project_version_indexes(refs)
        names = sorted((ref.project, ref.version, ref.version_href) for ref in refs)
        self.inventory_digest = hashlib.sha256(
            json.dumps(names, separators=(",", ":")).encode()
        ).hexdigest()
        self.identity = {
            "base_url": client.base_url.rstrip("/"),
            "resolve_bom_names": bool(resolve_bom_names),
        }
        self.entries = {}
        self.reused = 0
        self.scanned = 0
        if self.path.is_file() and not refresh:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload = {}
            if (
                isinstance(payload, dict)
                and payload.get("schema_version") == 1
                and payload.get("identity") == self.identity
                and isinstance(payload.get("entries"), dict)
            ):
                self.entries = payload["entries"]

    def signature(self, ref):
        return {
            "parent": asdict(ref),
            "inventory_digest": self.inventory_digest if self.resolve_bom_names else "",
        }

    def load(self, ref):
        signature = self.signature(ref)
        entry = self.entries.get(ref.version_href)
        if isinstance(entry, dict) and ref.updated and entry.get("signature") == signature:
            try:
                scanned = datetime.fromisoformat(entry["scanned_at"])
                age = (datetime.now(timezone.utc) - scanned).total_seconds()
                stored = entry["contexts"]
                if not isinstance(stored, list):
                    raise ValueError("Invalid cached contexts")
                contexts = []
                for value in stored:
                    child = ProjectVersionRef(**value["child"])
                    if child.version_href not in self.by_href:
                        raise ValueError("Cached child is no longer in inventory")
                    contexts.append(LineageContext(
                        parent=ref,
                        child=self.by_href[child.version_href],
                        detection_method=value["detection_method"],
                        bom_component_name=value["bom_component_name"],
                        bom_component_version=value["bom_component_version"],
                    ))
                if 0 <= age < 7 * 86400:
                    self.reused += 1
                    return contexts
            except (KeyError, TypeError, ValueError):
                pass

        contexts = discover_lineage_contexts(
            self.client,
            ref,
            self.by_href,
            self.by_name,
            resolve_bom_names=self.resolve_bom_names,
            debug=self.client.debug,
        )
        for context in contexts:
            if context.detection_method == "bom-component-name-version":
                key = (context.bom_component_name, context.bom_component_version)
                if len(self.by_name.get(key, [])) != 1:
                    raise RuntimeError("Ambiguous added-project name/version relationship")
            if context.child.version_href not in self.by_href:
                raise RuntimeError("Discovered child is outside the complete inventory")

        self.scanned += 1
        self.entries[ref.version_href] = {
            "signature": signature,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "contexts": [{
                "child": asdict(context.child),
                "detection_method": context.detection_method,
                "bom_component_name": context.bom_component_name,
                "bom_component_version": context.bom_component_version,
            } for context in contexts],
        }
        return contexts

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f"{self.path.name}.{uuid.uuid4().hex}.tmp")
        payload = {
            "schema_version": 1,
            "identity": self.identity,
            "entries": {
                href: entry for href, entry in self.entries.items()
                if href in self.by_href
            },
        }
        try:
            with temporary.open("w", encoding="utf-8") as output:
                json.dump(payload, output, indent=2, sort_keys=True, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
