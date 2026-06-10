#!/usr/bin/env python3
"""
ManifestService: Generates manifest.json for the SPA report viewer.

Replaces HTML report generation with a lightweight JSON manifest that
the Vue SPA consumes to render reports client-side.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..version import __version__

logger = logging.getLogger(__name__)

LOG_VIEWER_FILES = {
    "nvdebug_runtime_output.txt",
    "nvdebug_runtime_output_structured.txt",
}

EXT_TYPE_MAP = {
    ".json": "json",
    ".txt": "text",
    ".log": "log",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}

EXCLUDED_DIRS = {".metadata", "__pycache__", ".git"}

METADATA_SKIP_FILES = {
    "metadata.json",
    "preflight.json",
    "dependency_check.json",
    "collection_status.json",
    "timing.json",
    "system_info.json",
}


class ManifestService:
    """Generates a manifest.json from collected log data."""

    def __init__(self, log_dir: Path, spa_dist_dir: Optional[Path] = None):
        self.log_dir = Path(log_dir)
        self.spa_dist_dir = spa_dist_dir

    async def generate_manifest(self) -> Dict[str, Any]:
        """Build the complete manifest dict from the log directory."""
        manifest: Dict[str, Any] = {
            "schema_version": "2.0",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_version": __version__,
            "tool_config": self._read_tool_config(),
            "duts": [],
            "collector_catalog": self._read_collector_catalog(),
            "timing": {},
            "file_index": [],
            "errors": [],
            "preflight": {"per_dut": []},
            "dependency_check": {"per_dut": []},
            "collection_summary": {},
        }

        dut_dirs = self._find_dut_directories()
        logger.info("Found %d DUT directories in %s", len(dut_dirs), self.log_dir)

        for dut_dir in dut_dirs:
            dut_id = dut_dir.name
            try:
                dut = await self._process_dut(dut_dir)
                manifest["duts"].append(dut)
            except Exception as e:
                logger.error("Failed to process DUT %s: %s", dut_id, e, exc_info=True)
                manifest["errors"].append(
                    {
                        "dut_id": dut_id,
                        "collector_id": "",
                        "collector_name": "",
                        "collector_group": "",
                        "message": f"Failed to process DUT directory: {e}",
                        "timestamp": None,
                    }
                )
                continue

            dut_files = self._build_file_index(dut_dir, dut_id)
            self._enrich_file_index(dut_files, dut)
            manifest["file_index"].extend(dut_files)

            dut_errors = self._extract_errors(dut_dir, dut_id)
            manifest["errors"].extend(dut_errors)

            preflight = self._read_preflight(dut_dir, dut_id)
            if preflight:
                manifest["preflight"]["per_dut"].append(preflight)

            dependency = self._read_dependency_check(dut_dir, dut_id)
            if dependency:
                manifest["dependency_check"]["per_dut"].append(dependency)

        manifest["timing"] = self._build_timing_data()
        manifest["collection_summary"] = self._compute_summary(manifest)

        logger.info(
            "Manifest generated: %d DUTs, %d files, %d errors",
            len(manifest["duts"]),
            len(manifest["file_index"]),
            len(manifest["errors"]),
        )

        return manifest

    async def generate_report(self, report_dir: Path) -> Path:
        """Generate manifest and create the report directory with SPA assets."""
        report_dir = Path(report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)

        manifest = await self.generate_manifest()

        # Copy SPA assets if available
        if self.spa_dist_dir and self.spa_dist_dir.exists():
            self._copy_spa_assets(report_dir)

        # Write manifest and embed in index.html
        manifest_json = json.dumps(manifest, indent=2, default=str)

        # Write standalone manifest.json
        manifest_path = report_dir / "manifest.json"
        manifest_path.write_text(manifest_json, encoding="utf-8")

        # Embed in index.html if it exists
        index_html = report_dir / "index.html"
        if index_html.exists():
            self._embed_manifest(index_html, manifest_json)

        return index_html if index_html.exists() else manifest_path

    def _find_dut_directories(self) -> List[Path]:
        """Find DUT subdirectories (those with Execution_Summary_Report.txt or .metadata/)."""
        dut_dirs = []
        if not self.log_dir.exists():
            return dut_dirs

        for entry in sorted(self.log_dir.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name.startswith(".") or entry.name == "reports":
                continue
            # A DUT directory has either an execution summary or metadata
            has_summary = (entry / "Execution_Summary_Report.txt").exists()
            has_metadata = (entry / ".metadata").is_dir() or (
                entry / "metadata"
            ).is_dir()
            if has_summary or has_metadata:
                dut_dirs.append(entry)

        return dut_dirs

    async def _process_dut(self, dut_dir: Path) -> Dict[str, Any]:
        """Process a single DUT directory into a DUT manifest entry."""
        dut_id = dut_dir.name
        metadata_dir = dut_dir / ".metadata"
        if not metadata_dir.exists():
            metadata_dir = dut_dir / "metadata"

        system_info = self._extract_system_info(metadata_dir, dut_dir)

        # Read collector groups from metadata and enrich collector entries with
        # timing_data captured in .metadata/metadata.json.
        timing_lookup = self._build_collector_timing_lookup(dut_dir)
        collector_groups = self._build_collector_groups(
            metadata_dir, dut_dir, timing_lookup
        )

        # Compute status summary
        status_counts = {
            "success": 0,
            "error": 0,
            "partial": 0,
            "skipped": 0,
            "not_ran": 0,
        }
        for group in collector_groups:
            for collector in group.get("collectors", []):
                status = collector.get("status", "unknown")
                if status in status_counts:
                    status_counts[status] += 1

        # Determine overall status
        if status_counts["error"] > 0:
            overall_status = "error"
        elif status_counts["partial"] > 0:
            overall_status = "partial"
        elif status_counts["success"] > 0:
            overall_status = "success"
        elif status_counts["skipped"] > 0:
            overall_status = "skipped"
        else:
            overall_status = "unknown"

        # Read execution time from timing
        execution_time = self._get_dut_execution_time(metadata_dir, dut_dir)

        # Calculate log size
        log_size = self._calculate_dir_size(dut_dir)

        return {
            "id": dut_id,
            "baseboard": self._get_baseboard(dut_dir),
            "node_type": self._get_node_type(dut_dir),
            "bmc_ip": self._get_bmc_ip(dut_dir),
            "collector_groups": collector_groups,
            "status_summary": status_counts,
            "overall_status": overall_status,
            "execution_time": execution_time,
            "log_size": log_size,
            "system_info": system_info,
        }

    def _build_collector_groups(
        self,
        metadata_dir: Path,
        dut_dir: Path,
        timing_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Dict]:
        """Build collector groups from metadata JSON files."""
        groups = []
        if not metadata_dir.exists():
            return groups
        timing_lookup = timing_lookup or {}

        # Each service metadata file (redfish.json, host.json, etc.) contains collector results
        service_files = {
            "redfish.json": "redfish",
            "host.json": "host",
            "ipmi.json": "ipmi",
            "ssh.json": "ssh",
            "bmc_ssh.json": "ssh",
            "health_check.json": "health_check",
            "healthcheck.json": "health_check",
        }

        for filename, service_type in service_files.items():
            meta_path = metadata_dir / filename
            if not meta_path.exists():
                continue

            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            collectors = []
            if isinstance(meta, dict):
                # The metadata JSON has a "collectors" key containing the actual
                # collector results. Top-level keys like "metadata", "status_fields",
                # "summary" are not collectors.
                collector_dict = meta.get("collectors", {})
                if not isinstance(collector_dict, dict):
                    collector_dict = {}
                # Fallback: if no "collectors" key, check if top-level keys look
                # like collector IDs (e.g., "R1", "H2") — older format
                if not collector_dict:
                    for key, val in meta.items():
                        if (
                            isinstance(val, dict)
                            and key not in ("metadata", "status_fields", "summary")
                            and (
                                val.get("id")
                                or val.get("status")
                                or val.get("files")
                                or val.get("log_paths")
                            )
                        ):
                            collector_dict[key] = val
                for collector_id, collector_data in collector_dict.items():
                    if not isinstance(collector_data, dict):
                        continue
                    collectors.append(
                        self._parse_collector(
                            collector_id, collector_data, dut_dir, service_type
                        )
                    )

            for collector in collectors:
                self._apply_timing_to_collector(collector, timing_lookup)
            total_time = sum(c.get("execution_time", 0) for c in collectors)

            groups.append(
                {
                    "name": service_type,
                    "service_type": service_type,
                    "collectors": collectors,
                    "total_execution_time": total_time,
                }
            )

        return groups

    def _build_collector_timing_lookup(
        self, dut_dir: Path
    ) -> Dict[str, Dict[str, Any]]:
        """Build an uppercase collector-id to timing payload lookup."""
        lookup: Dict[str, Dict[str, Any]] = {}
        for timing_source in (
            self._read_metadata_timing(dut_dir),
            self._read_timing_json(dut_dir),
        ):
            if not timing_source:
                continue
            collectors = timing_source.get("collectors", {})
            if not isinstance(collectors, dict):
                continue
            for collector_id, timing_data in collectors.items():
                if isinstance(timing_data, dict):
                    key = str(collector_id).upper()
                    existing = lookup.get(key, {})
                    merged = {**existing, **timing_data}
                    existing_stages = existing.get("stage_timing") or existing.get(
                        "stages"
                    )
                    new_stages = timing_data.get("stage_timing") or timing_data.get(
                        "stages"
                    )
                    if isinstance(existing_stages, dict) and existing_stages:
                        if not isinstance(new_stages, dict) or not new_stages:
                            merged["stages"] = existing_stages
                    lookup[key] = merged
        return lookup

    def _apply_timing_to_collector(
        self, collector: Dict[str, Any], timing_lookup: Dict[str, Dict[str, Any]]
    ) -> None:
        """Overlay collector duration and stage timing from timing metadata."""
        timing_data = timing_lookup.get(str(collector.get("id", "")).upper())
        if not timing_data:
            return

        duration = timing_data.get(
            "duration_seconds",
            timing_data.get("duration", timing_data.get("total_time")),
        )
        if duration is not None:
            collector["execution_time"] = float(duration or 0)

        stages = timing_data.get("stage_timing") or timing_data.get("stages", {})
        if not isinstance(stages, dict):
            return

        stage_timing = collector.setdefault(
            "stage_timing",
            {
                "validation": None,
                "discovery": None,
                "execution": None,
                "post_processing": None,
            },
        )
        for stage_name in ("validation", "discovery", "execution", "post_processing"):
            if stage_name in stages:
                stage_timing[stage_name] = self._normalize_stage_value(
                    stages.get(stage_name)
                )

    def _parse_collector(
        self, collector_id: str, data: Dict, dut_dir: Path, service_type: str
    ) -> Dict:
        """Parse a single collector entry from metadata."""
        # Normalize status
        raw_status = str(data.get("status", "unknown")).lower()
        status_map = {
            "complete": "success",
            "passed": "success",
            "success": "success",
            "error": "error",
            "failed": "error",
            "partial": "partial",
            "skipped": "skipped",
            "not_ran": "not_ran",
            "notran": "not_ran",
        }
        status = status_map.get(raw_status, "not_ran")

        # Extract files
        files = []
        seen_paths = set()
        for file_path in data.get("files", data.get("log_paths", [])):
            if isinstance(file_path, str):
                abs_path = (
                    Path(file_path)
                    if Path(file_path).is_absolute()
                    else dut_dir / file_path
                )
                if abs_path.exists():
                    try:
                        rel_path = str(abs_path.relative_to(self.log_dir))
                    except ValueError:
                        rel_path = str(file_path)
                    norm_rel_path = rel_path.replace("\\", "/")
                    if norm_rel_path not in seen_paths:
                        files.append(
                            self._make_file_ref(norm_rel_path, abs_path, collector_id)
                        )
                        seen_paths.add(norm_rel_path)

        self._append_status_artifacts(
            files, seen_paths, collector_id, dut_dir, service_type
        )

        return {
            "id": collector_id,
            "name": data.get("name", collector_id),
            "status": status,
            "execution_time": float(
                data.get("execution_time", data.get("duration", 0)) or 0
            ),
            "start_time": data.get("start_time"),
            "end_time": data.get("end_time"),
            "reason": str(data.get("reason", data.get("error", "")) or ""),
            "dependencies": data.get("dependencies", []),
            "collection_level": data.get("collection_level", ""),
            "files": files,
            "stage_timing": {
                "validation": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("validation")
                ),
                "discovery": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("discovery")
                ),
                "execution": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("execution")
                ),
                "post_processing": self._normalize_stage_value(
                    data.get("stage_timing", {}).get("post_processing")
                ),
            },
        }

    def _append_status_artifacts(
        self,
        files: List[Dict],
        seen_paths: set,
        collector_id: str,
        dut_dir: Path,
        service_type: str,
    ) -> None:
        """Backfill artifacts referenced from per-collector status.json."""
        status_path = self._find_collector_status_file(
            collector_id, files, dut_dir, service_type
        )
        if not status_path or not status_path.exists():
            return

        try:
            status_data = json.loads(status_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        artifact_names = []
        for artifact_key in ("command_execution", "request_response_capture"):
            artifact_name = (status_data.get(artifact_key, {}) or {}).get("artifact")
            if artifact_name:
                artifact_names.append(artifact_name)

        for artifact_name in artifact_names:
            artifact_path = status_path.parent / artifact_name
            if not artifact_path.exists():
                continue

            try:
                rel_path = str(artifact_path.relative_to(self.log_dir)).replace(
                    "\\", "/"
                )
            except ValueError:
                rel_path = str(artifact_path)

            if rel_path in seen_paths:
                continue

            files.append(self._make_file_ref(rel_path, artifact_path, collector_id))
            seen_paths.add(rel_path)

    def _find_collector_status_file(
        self,
        collector_id: str,
        files: List[Dict],
        dut_dir: Path,
        service_type: str,
    ) -> Optional[Path]:
        """Locate a collector's status.json file."""
        for file_ref in files:
            file_path = self.log_dir / file_ref["path"]
            status_path = file_path.parent / "status.json"
            if status_path.exists():
                return status_path

        group_dir = dut_dir / service_type
        if not group_dir.exists():
            return None

        collector_token = collector_id
        service_prefix = service_type.capitalize()
        matches = sorted(
            group_dir.glob(f"{service_prefix}_{collector_token}_*/status.json")
        )
        if matches:
            return matches[0]

        return None

    @staticmethod
    def _normalize_stage_value(val: Any) -> Optional[float]:
        """Normalize a stage_timing value to float or None.

        Handles nested dicts like {"total_time": 0.5, "duration": 0.5}.
        """
        if isinstance(val, dict):
            raw = val.get("total_time", val.get("duration", 0))
            return float(raw or 0)
        elif isinstance(val, (int, float)):
            return float(val)
        return None

    def _make_file_ref(self, rel_path: str, abs_path: Path, collector_id: str) -> Dict:
        """Create a FileRef dict for a file."""
        ext = abs_path.suffix.lower()
        file_type = EXT_TYPE_MAP.get(ext, "binary")

        ref = {
            "path": rel_path.replace("\\", "/"),
            "size": abs_path.stat().st_size if abs_path.exists() else 0,
            "type": file_type,
            "collector_id": collector_id,
        }

        # Set viewer_hint for known log files
        name = abs_path.name
        if name in LOG_VIEWER_FILES or name.endswith("_stdout.log"):
            ref["viewer_hint"] = "log-viewer"

        return ref

    def _build_file_index(self, dut_dir: Path, dut_id: str) -> List[Dict]:
        """Walk a DUT directory and build the file index."""
        files = []
        for root, dirs, filenames in os.walk(dut_dir):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

            root_path = Path(root)
            for filename in sorted(filenames):
                file_path = root_path / filename
                try:
                    rel_path = str(file_path.relative_to(self.log_dir)).replace(
                        "\\", "/"
                    )
                except ValueError:
                    continue

                ext = file_path.suffix.lower()
                file_type = EXT_TYPE_MAP.get(ext, "binary")

                try:
                    file_size = file_path.stat().st_size
                except OSError:
                    continue

                entry = {
                    "path": rel_path,
                    "size": file_size,
                    "type": file_type,
                    "collector_id": "",  # Will be enriched if matched to a collector
                    "dut_id": dut_id,
                    "collector_group": self._infer_group(root_path, dut_dir),
                    "collector_name": "",
                }

                # Set viewer_hint
                if filename in LOG_VIEWER_FILES or filename.endswith("_stdout.log"):
                    entry["viewer_hint"] = "log-viewer"

                files.append(entry)

        return files

    @staticmethod
    def _enrich_file_index(file_entries: List[Dict], dut: Dict[str, Any]) -> None:
        """Enrich file_index entries with collector_id/name from DUT collector data."""
        path_to_collector: Dict[str, tuple] = {}
        for group in dut.get("collector_groups", []):
            for collector in group.get("collectors", []):
                cid = collector.get("id", "")
                cname = collector.get("name", "")
                for fref in collector.get("files", []):
                    p = fref.get("path", "")
                    if p:
                        path_to_collector[p.replace("\\", "/")] = (cid, cname)

        for entry in file_entries:
            key = entry.get("path", "").replace("\\", "/")
            if key in path_to_collector:
                entry["collector_id"] = path_to_collector[key][0]
                entry["collector_name"] = path_to_collector[key][1]

    def _infer_group(self, file_dir: Path, dut_dir: Path) -> str:
        """Infer collector group from directory path."""
        try:
            rel = file_dir.relative_to(dut_dir)
            parts = rel.parts
            if parts:
                return parts[0]
        except ValueError:
            pass
        return ""

    def _extract_errors(self, dut_dir: Path, dut_id: str) -> List[Dict]:
        """Extract errors from metadata files."""
        errors = []
        metadata_dir = dut_dir / ".metadata"
        if not metadata_dir.exists():
            metadata_dir = dut_dir / "metadata"
        if not metadata_dir.exists():
            return errors

        for meta_file in metadata_dir.glob("*.json"):
            if meta_file.name in ("timing.json", "preflight.json"):
                continue
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            if isinstance(meta, dict):
                # Extract collectors dict (same logic as _build_collector_groups)
                collector_dict = meta.get("collectors", {})
                if not isinstance(collector_dict, dict):
                    collector_dict = {}
                if not collector_dict:
                    for key, val in meta.items():
                        if (
                            isinstance(val, dict)
                            and key not in ("metadata", "status_fields", "summary")
                            and (
                                val.get("id")
                                or val.get("status")
                                or val.get("files")
                                or val.get("log_paths")
                            )
                        ):
                            collector_dict[key] = val
                for collector_id, data in collector_dict.items():
                    if not isinstance(data, dict):
                        continue
                    status = str(data.get("status", "")).lower()
                    if status in ("error", "failed", "partial"):
                        errors.append(
                            {
                                "dut_id": dut_id,
                                "collector_id": collector_id,
                                "collector_name": data.get("name", collector_id),
                                "collector_group": meta_file.stem,
                                "message": str(
                                    data.get(
                                        "reason", data.get("error", "Unknown error")
                                    )
                                    or "Unknown error"
                                ),
                                "timestamp": data.get("start_time"),
                            }
                        )

        return errors

    def _read_preflight(self, dut_dir: Path, dut_id: str) -> Optional[Dict]:
        """Read preflight check data from .metadata/preflight.json.

        The preflight file structure has a nested 'preflights' dict:
        {"preflights": {"HOST": {"status": "...", "reason": "..."}, ...}}
        """
        for metadata_name in (".metadata", "metadata"):
            preflight_path = dut_dir / metadata_name / "preflight.json"
            if preflight_path.exists():
                break
        else:
            logger.debug("No preflight.json found for DUT %s", dut_id)
            return None

        try:
            with open(preflight_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read preflight.json for DUT %s: %s", dut_id, e)
            return None

        checks = []
        if isinstance(data, dict):
            preflights = data.get("preflights", {})
            if not isinstance(preflights, dict) or not preflights:
                preflights = {
                    k: v
                    for k, v in data.items()
                    if isinstance(v, dict) and k != "metadata"
                }

            for check_name, check_data in preflights.items():
                if not isinstance(check_data, dict):
                    continue
                checks.append(
                    {
                        "name": check_name,
                        "group": check_data.get("group", check_name.lower()),
                        "status": str(check_data.get("status", "na")).lower(),
                        "details": str(
                            check_data.get(
                                "reason",
                                check_data.get(
                                    "details", check_data.get("message", "")
                                ),
                            )
                            or ""
                        ),
                    }
                )

        if checks:
            logger.debug("Read %d preflight checks for DUT %s", len(checks), dut_id)
        return {"dut_id": dut_id, "checks": checks} if checks else None

    def _read_tool_config(self) -> Dict:
        """Read tool config from any DUT's config.json."""
        for dut_dir in self._find_dut_directories():
            config_path = dut_dir / "config.json"
            if config_path.exists():
                try:
                    with open(config_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass
        return {
            "collection_level": "unknown",
            "execution_mode": "unknown",
            "baseboard": "unknown",
        }

    def _read_collector_catalog(self) -> List[Dict]:
        """Read collector catalog from root-level file."""
        catalog_path = self.log_dir / "collector_catalog.json"
        if not catalog_path.exists():
            return []
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _build_timing_data(self) -> Dict:
        """Build timing data from DUT timing.json and metadata.json files.

        timing.json structure:
            {"overall": {"wall_clock_duration_seconds": N}, "collectors": {ID: {...}}, "by_service": {...}}
        metadata.json timing:
            {"payload": {"timing_data": {"collectors": {ID: {"total_time": N, "stages": {...}}}}}}
        """
        timing: Dict[str, Any] = {
            "total_duration": 0,
            "component_timing": {
                "tool_init": None,
                "config_load": None,
                "dut_init": None,
                "preflight": None,
                "collection": None,
                "report_generation": None,
                "metadata_write": None,
                "cleanup": None,
            },
            "per_dut": [],
            "per_service": [],
        }

        service_totals: Dict[str, Dict] = {}

        for dut_dir in self._find_dut_directories():
            dut_id = dut_dir.name
            dut_timing = self._read_timing_json(dut_dir)
            metadata_timing = self._read_metadata_timing(dut_dir)

            if not dut_timing and not metadata_timing:
                continue

            overall = dut_timing.get("overall", {}) if dut_timing else {}
            duration = float(
                overall.get(
                    "wall_clock_duration_seconds",
                    overall.get(
                        "duration_seconds",
                        (
                            dut_timing.get(
                                "total_duration", dut_timing.get("duration", 0)
                            )
                            if dut_timing
                            else 0
                        ),
                    ),
                )
                or 0
            )
            timing["total_duration"] = max(timing["total_duration"], duration)

            if (
                dut_timing
                and dut_timing.get("component_timing")
                and all(v is None for v in timing["component_timing"].values())
            ):
                timing["component_timing"] = dut_timing["component_timing"]

            collectors = self._parse_timing_collectors(
                dut_timing, metadata_timing, service_totals
            )

            timing["per_dut"].append(
                {
                    "dut_id": dut_id,
                    "duration": duration,
                    "collectors": collectors,
                }
            )

        timing["per_service"] = [
            {"service": svc, **totals} for svc, totals in sorted(service_totals.items())
        ]

        return timing

    def _read_timing_json(self, dut_dir: Path) -> Optional[Dict]:
        """Read timing.json from a DUT's metadata directory."""
        for metadata_name in (".metadata", "metadata"):
            timing_path = dut_dir / metadata_name / "timing.json"
            if timing_path.exists():
                try:
                    with open(timing_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    return data if isinstance(data, dict) else None
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(
                        "Failed to read timing.json for %s: %s", dut_dir.name, e
                    )
        return None

    def _read_metadata_timing(self, dut_dir: Path) -> Optional[Dict]:
        """Read timing_data from metadata.json payload."""
        for metadata_name in (".metadata", "metadata"):
            meta_path = dut_dir / metadata_name / "metadata.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    timing_data = data.get("payload", {}).get("timing_data", {})
                    return (
                        timing_data
                        if isinstance(timing_data, dict) and timing_data
                        else None
                    )
                except (json.JSONDecodeError, OSError):
                    pass
        return None

    def _parse_timing_collectors(
        self,
        dut_timing: Optional[Dict],
        metadata_timing: Optional[Dict],
        service_totals: Dict[str, Dict],
    ) -> List[Dict]:
        """Parse collector timing from timing.json (dict format) and metadata.json."""
        collectors: List[Dict] = []
        seen_ids: set = set()

        if dut_timing:
            raw_collectors = dut_timing.get("collectors", {})
            if isinstance(raw_collectors, dict):
                items = raw_collectors.items()
            elif isinstance(raw_collectors, list):
                items = (
                    (c.get("id", ""), c) for c in raw_collectors if isinstance(c, dict)
                )
            else:
                items = iter([])

            for coll_id, coll in items:
                if not isinstance(coll, dict):
                    continue
                seen_ids.add(coll_id)
                group = coll.get("group", coll.get("service", ""))
                dur = float(
                    coll.get(
                        "duration_seconds",
                        coll.get("duration", coll.get("total_time", 0)),
                    )
                    or 0
                )

                stage_timing = coll.get("stage_timing", coll.get("stages", {}))
                if isinstance(stage_timing, dict):
                    normalized_stages = {}
                    for stage_name, stage_val in stage_timing.items():
                        if isinstance(stage_val, dict):
                            normalized_stages[stage_name] = float(
                                stage_val.get(
                                    "total_time", stage_val.get("duration", 0)
                                )
                                or 0
                            )
                        elif isinstance(stage_val, (int, float)):
                            normalized_stages[stage_name] = float(stage_val)
                        else:
                            normalized_stages[stage_name] = None
                else:
                    normalized_stages = {}

                collectors.append(
                    {
                        "id": coll_id or coll.get("id", ""),
                        "name": coll.get("name", coll_id),
                        "group": group,
                        "duration": dur,
                        "start_time": coll.get("start_time"),
                        "end_time": coll.get("end_time"),
                        "status": coll.get("status", ""),
                        "stage_timing": {
                            "validation": normalized_stages.get("validation"),
                            "discovery": normalized_stages.get("discovery"),
                            "execution": normalized_stages.get("execution"),
                            "post_processing": normalized_stages.get("post_processing"),
                        },
                    }
                )

                if group and group not in service_totals:
                    service_totals[group] = {"total_collectors": 0, "total_duration": 0}
                if group:
                    service_totals[group]["total_collectors"] += 1
                    service_totals[group]["total_duration"] += dur

        if metadata_timing:
            meta_collectors = metadata_timing.get("collectors", {})
            if isinstance(meta_collectors, dict):
                for coll_id, coll in meta_collectors.items():
                    if not isinstance(coll, dict):
                        continue
                    if coll_id in seen_ids:
                        stages_raw = coll.get("stages", {})
                        if isinstance(stages_raw, dict) and stages_raw:
                            for existing in collectors:
                                if existing["id"] == coll_id:
                                    for sname, sval in stages_raw.items():
                                        if isinstance(sval, dict):
                                            existing["stage_timing"][sname] = float(
                                                sval.get("total_time", 0) or 0
                                            )
                                        elif isinstance(sval, (int, float)):
                                            existing["stage_timing"][sname] = float(
                                                sval
                                            )
                                    break
                        continue
                    dur = float(coll.get("total_time", 0) or 0)
                    stages_raw = coll.get("stages", {})
                    normalized_stages = {}
                    if isinstance(stages_raw, dict):
                        for sname, sval in stages_raw.items():
                            if isinstance(sval, dict):
                                normalized_stages[sname] = float(
                                    sval.get("total_time", 0) or 0
                                )
                            elif isinstance(sval, (int, float)):
                                normalized_stages[sname] = float(sval)
                    group = coll.get("group", coll.get("service", ""))
                    collectors.append(
                        {
                            "id": coll_id,
                            "name": coll.get("name", coll_id),
                            "group": group,
                            "duration": dur,
                            "start_time": coll.get("start_time"),
                            "end_time": coll.get("end_time"),
                            "status": coll.get("status", ""),
                            "stage_timing": {
                                "validation": normalized_stages.get("validation"),
                                "discovery": normalized_stages.get("discovery"),
                                "execution": normalized_stages.get("execution"),
                                "post_processing": normalized_stages.get(
                                    "post_processing"
                                ),
                            },
                        }
                    )
                    if group and group not in service_totals:
                        service_totals[group] = {
                            "total_collectors": 0,
                            "total_duration": 0,
                        }
                    if group:
                        service_totals[group]["total_collectors"] += 1
                        service_totals[group]["total_duration"] += dur

        return collectors

    def _extract_system_info(self, metadata_dir: Path, dut_dir: Path) -> Dict:
        """Extract system FRU info from metadata.json (payload.PlatformModel, etc.)
        with fallback to nvdebug_runtime_output.txt regex parsing."""
        info: Dict[str, Any] = {
            "model": None,
            "part_number": None,
            "serial_number": None,
            "firmware": [],
        }

        if metadata_dir.exists():
            meta_path = metadata_dir / "metadata.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    payload = data.get("payload", {})
                    if isinstance(payload, dict):
                        info["model"] = payload.get("PlatformModel", "").strip() or None
                        info["part_number"] = (
                            payload.get("PartNumber", "").strip() or None
                        )
                        info["serial_number"] = (
                            payload.get("SerialNumber", "").strip() or None
                        )
                        logger.debug(
                            "System info from metadata.json: model=%s part=%s serial=%s",
                            info["model"],
                            info["part_number"],
                            info["serial_number"],
                        )
                except (json.JSONDecodeError, OSError, AttributeError) as e:
                    logger.warning(
                        "Failed to read metadata.json in %s: %s", metadata_dir, e
                    )

        if not info["model"]:
            runtime_path = dut_dir / "nvdebug_runtime_output.txt"
            if runtime_path.exists():
                try:
                    text = runtime_path.read_text(encoding="utf-8", errors="replace")
                    model_match = re.search(r"Platform Model:\s*(.+)", text)
                    part_match = re.search(r"Part Number:\s*(.+)", text)
                    serial_match = re.search(r"Serial Number:\s*(.+)", text)
                    if model_match:
                        info["model"] = model_match.group(1).strip() or None
                    if part_match:
                        info["part_number"] = part_match.group(1).strip() or None
                    if serial_match:
                        info["serial_number"] = serial_match.group(1).strip() or None

                    if not info["model"]:
                        legacy_match = re.search(
                            r"Identified system as Model:\s*(?P<model>[^,]+)"
                            r",\s*Partno:\s*(?P<part>[^,]+)"
                            r",\s*Serialno:\s*(?P<ser>\S+)",
                            text,
                        )
                        if legacy_match:
                            info["model"] = legacy_match.group("model").strip() or None
                            info["part_number"] = (
                                legacy_match.group("part").strip() or None
                            )
                            info["serial_number"] = (
                                legacy_match.group("ser").strip() or None
                            )

                    logger.debug(
                        "System info from runtime output fallback: %s", info["model"]
                    )
                except OSError as e:
                    logger.warning(
                        "Failed to read runtime output in %s: %s", dut_dir, e
                    )

        info["firmware"] = self._extract_firmware_from_redfish(dut_dir)
        info["system_view"] = self._extract_system_view(dut_dir, info)

        return info

    def _extract_system_view(
        self, dut_dir: Path, system_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract the compact system view used by the dashboard modal.

        The report is generated from collected logs, so every field is optional and
        depends on which collectors were run. Parsers intentionally accept both the
        current collector output names and older command-wrapper files.
        """
        firmware = system_info.get("firmware", [])

        host_os_text = self._read_first_matching_text(
            dut_dir,
            [
                "host/**/Host_H18_os_release.txt",
                "host/**/*os_release.txt",
            ],
        )
        host_uname_text = self._read_first_matching_text(
            dut_dir,
            [
                "host/**/Host_H18_uname_-a.txt",
                "host/**/*uname_-a.txt",
            ],
        )
        host_uptime_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H18_uptime.txt", "host/**/*uptime.txt"]
        )
        host_top_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H18_top_-bn1.txt", "host/**/*top_-bn1.txt"]
        )
        host_free_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H18_free_m.txt", "host/**/Host_H19_free_m.txt"]
        )
        host_meminfo_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H19_meminfo.txt", "host/**/*meminfo.txt"]
        )
        host_df_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H18_df_-kh.txt", "host/**/*df_-kh.txt"]
        )
        nvidia_smi_text = self._read_first_matching_text(
            dut_dir,
            [
                "host/**/Host_H5_nvidia-smi_-q.txt",
                "host/**/Host_H5_nvidia-smi.txt",
                "host/**/*nvidia-smi*.txt",
            ],
        )
        dcgmi_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H5_dcgmi_--version.txt", "host/**/*dcgmi*.txt"]
        )
        dmidecode_text = self._read_first_matching_text(
            dut_dir, ["host/**/Host_H3_dmidecode.txt", "host/**/*dmidecode.txt"]
        )

        bmc_os_text = self._read_first_matching_text(
            dut_dir,
            [
                "ssh/**/SSH_S4_bmc_stack_info.txt",
                "ssh/**/*bmc_stack_info.txt",
                "ssh/**/*os-release*.txt",
            ],
        )
        bmc_uname_text = self._read_first_matching_text(
            dut_dir, ["ssh/**/SSH_S8_uname_-a.txt", "ssh/**/*S8*uname*.txt"]
        ) or self._read_collector_command_output(dut_dir, "S8", r"\buname\s+-a\b")
        bmc_uptime_text = self._read_first_matching_text(
            dut_dir, ["ssh/**/SSH_S11_uptime.txt", "ssh/**/*S11*uptime*.txt"]
        ) or self._read_collector_command_output(dut_dir, "S11", r"\buptime\b")
        bmc_top_text = self._read_collector_command_output(
            dut_dir, "S8", r"\btop\b"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*S8*top*.txt"])
        bmc_proc_stat_text = self._read_first_matching_text(
            dut_dir,
            [
                "ssh/**/SSH_S8_proc_stat_cpu_sample.txt",
                "ssh/**/*proc_stat_cpu_sample*.txt",
            ],
        ) or self._read_collector_command_output(dut_dir, "S8", r"/proc/stat")
        bmc_meminfo_text = self._read_collector_command_output(
            dut_dir, "S8", r"/proc/meminfo"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*S8*meminfo*.txt"])
        bmc_df_text = self._read_collector_command_output(
            dut_dir, "S8", r"\bdf\s+-kh\b"
        ) or self._read_first_matching_text(dut_dir, ["ssh/**/*S8*df*.txt"])

        host_os = self._parse_os_release_name(host_os_text)
        host_kernel = self._parse_uname_kernel(host_uname_text)
        bmc_version = self._extract_bmc_version(dut_dir, firmware, bmc_os_text)

        return {
            "bmc": {
                "version": bmc_version,
                "os": self._parse_os_release_name(bmc_os_text),
                "kernel": self._parse_uname_kernel(bmc_uname_text),
                "uptime": self._parse_uptime(bmc_uptime_text),
                "utilization": self._parse_utilization(
                    top_text=bmc_top_text,
                    proc_stat_text=bmc_proc_stat_text,
                    free_text=None,
                    meminfo_text=bmc_meminfo_text,
                    df_text=bmc_df_text,
                ),
            },
            "host": {
                "os": host_os,
                "kernel": host_kernel,
                "uptime": self._parse_uptime(host_uptime_text),
                "utilization": self._parse_utilization(
                    top_text=host_top_text,
                    free_text=host_free_text,
                    meminfo_text=host_meminfo_text,
                    df_text=host_df_text,
                ),
            },
            "software": {
                "host_os": host_os,
                "kernel_version": host_kernel,
                "bmc_version": bmc_version,
                "sbios": self._parse_bios_version(dmidecode_text),
                "rm_driver_version": self._parse_nvidia_field(
                    nvidia_smi_text, "driver"
                ),
                "cuda_driver_version": self._parse_nvidia_field(
                    nvidia_smi_text, "cuda"
                ),
                "dcgm_version": self._parse_dcgm_version(dcgmi_text),
            },
        }

    def _read_text_file(self, path: Path) -> Optional[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _read_first_matching_text(
        self, dut_dir: Path, patterns: List[str]
    ) -> Optional[str]:
        for pattern in patterns:
            for path in sorted(dut_dir.glob(pattern)):
                if path.is_file():
                    text = self._read_text_file(path)
                    if text:
                        return text
        return None

    def _read_collector_command_output(
        self, dut_dir: Path, collector_token: str, command_pattern: str
    ) -> Optional[str]:
        command_re = re.compile(command_pattern)
        token = collector_token.lower()
        for path in sorted(dut_dir.rglob("*.txt")):
            if token not in str(path).lower():
                continue
            text = self._read_text_file(path)
            if not text:
                continue
            command_match = re.search(r"^Command:\s*(.+)$", text, re.MULTILINE)
            if command_match and command_re.search(command_match.group(1)):
                return text
        return None

    def _command_output_body(self, text: Optional[str]) -> str:
        if not text:
            return ""
        output_marker = "\nOutput:\n"
        if output_marker in text:
            body = text.split(output_marker, 1)[1]
            if "\nError:\n" in body:
                body = body.split("\nError:\n", 1)[0]
            return body.strip()
        return text.strip()

    def _parse_os_release_name(self, text: Optional[str]) -> Optional[str]:
        values = self._parse_key_value_text(self._command_output_body(text))
        return (
            values.get("PRETTY_NAME")
            or values.get("NAME")
            or values.get("VERSION")
            or values.get("VERSION_ID")
        )

    def _parse_key_value_text(self, text: str) -> Dict[str, str]:
        values: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        return values

    def _parse_uname_kernel(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[0].lower() == "linux":
                return f"{parts[0]} {parts[2]}"
            return line
        return None

    def _parse_uptime(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.search(r"\bup\s+(.+?),\s+\d+\s+users?", line)
            if match:
                return match.group(1).strip()
            match = re.search(r"\bup\s+(.+?),\s+load average", line)
            if match:
                return match.group(1).strip()
            return line
        return None

    def _parse_utilization(
        self,
        *,
        top_text: Optional[str],
        proc_stat_text: Optional[str] = None,
        free_text: Optional[str],
        meminfo_text: Optional[str],
        df_text: Optional[str],
    ) -> Dict[str, Optional[str]]:
        return {
            "cpu": self._parse_cpu_from_proc_stat(proc_stat_text)
            or self._parse_cpu_from_top(top_text),
            "memory": self._parse_memory_from_free(free_text)
            or self._parse_memory_from_meminfo(meminfo_text),
            "disk": self._parse_disk_from_df(df_text),
        }

    def _parse_cpu_from_proc_stat(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        samples: List[Tuple[float, float]] = []

        for line in body.splitlines():
            parts = line.strip().split()
            if len(parts) < 5 or parts[0] != "cpu":
                continue
            try:
                values = [float(part) for part in parts[1:]]
            except ValueError:
                continue
            idle = values[3] + (values[4] if len(values) > 4 else 0.0)
            total = sum(values)
            samples.append((idle, total))

        if len(samples) < 2:
            return None

        first_idle, first_total = samples[0]
        last_idle, last_total = samples[-1]
        total_delta = last_total - first_total
        idle_delta = last_idle - first_idle
        if total_delta <= 0 or idle_delta < 0:
            return None

        used = (total_delta - idle_delta) / total_delta * 100.0
        used = min(100.0, max(0.0, used))
        return f"{used:.1f}%"

    def _parse_cpu_from_top(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        for line in body.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if "%cpu" not in lower and not lower.startswith("cpu:"):
                continue

            idle_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:%?\s*)id(?:le)?", lower)
            if idle_match:
                used = max(0.0, 100.0 - float(idle_match.group(1)))
                return f"{used:.1f}%"

            usr_match = re.search(r"(\d+(?:\.\d+)?)\s*%?\s*usr", lower)
            sys_match = re.search(r"(\d+(?:\.\d+)?)\s*%?\s*sys", lower)
            if usr_match or sys_match:
                used = float(usr_match.group(1)) if usr_match else 0.0
                used += float(sys_match.group(1)) if sys_match else 0.0
                return f"{used:.1f}%"
        return None

    def _parse_memory_from_free(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        for line in body.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].rstrip(":").lower() == "mem":
                try:
                    total = float(parts[1])
                    used = float(parts[2])
                except ValueError:
                    return None
                if total <= 0:
                    return None
                return f"{used / total * 100:.1f}% ({used:.0f}/{total:.0f} MB)"
        return None

    def _parse_memory_from_meminfo(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        values: Dict[str, float] = {}
        for line in body.splitlines():
            match = re.match(r"^(MemTotal|MemAvailable|MemFree):\s+(\d+)\s+kB", line)
            if match:
                values[match.group(1)] = float(match.group(2))
        total = values.get("MemTotal")
        available = values.get("MemAvailable", values.get("MemFree"))
        if not total or available is None or total <= 0:
            return None
        used = max(0.0, total - available)
        return f"{used / total * 100:.1f}% ({self._format_kib(used)}/{self._format_kib(total)})"

    def _parse_disk_from_df(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        candidates: List[Tuple[int, str]] = []
        for line in body.splitlines():
            parts = line.split()
            if len(parts) < 6 or not parts[-2].endswith("%"):
                continue
            try:
                used_pct = int(parts[-2].rstrip("%"))
            except ValueError:
                continue
            mount = parts[-1]
            if mount == "/":
                return f"{used_pct}% (/)"
            candidates.append((used_pct, mount))
        if candidates:
            used_pct, mount = max(candidates, key=lambda item: item[0])
            return f"{used_pct}% ({mount})"
        return None

    def _format_kib(self, value: float) -> str:
        mib = value / 1024
        if mib >= 1024:
            return f"{mib / 1024:.1f} GB"
        return f"{mib:.0f} MB"

    def _parse_bios_version(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        match = re.search(
            r"BIOS Information.*?^\s*Version:\s*([^\r\n]+)",
            body,
            re.MULTILINE | re.DOTALL,
        )
        if match:
            return match.group(1).strip()
        match = re.search(r"^\s*Version:\s*(.+)$", body, re.MULTILINE)
        return match.group(1).strip() if match else None

    def _parse_nvidia_field(self, text: Optional[str], field: str) -> Optional[str]:
        body = self._command_output_body(text)
        if not body:
            return None
        if field == "driver":
            patterns = [
                r"Driver Version\s*:\s*([^\n|]+)",
                r"Driver Version:\s*([^\s|]+)",
            ]
        else:
            patterns = [
                r"CUDA Version\s*:\s*([^\n|]+)",
                r"CUDA Version:\s*([^\s|]+)",
            ]
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1).strip()
        return None

    def _parse_dcgm_version(self, text: Optional[str]) -> Optional[str]:
        body = self._command_output_body(text)
        if not body:
            return None
        if re.search(r"not found|not installed|No such file", body, re.IGNORECASE):
            return "DCGM not installed and/or enabled"
        for pattern in (
            r"DCGM\s+Version\s*:?\s*([^\n]+)",
            r"dcgmi\s+version\s*:?\s*([^\n]+)",
            r"version\s*:?\s*([^\n]+)",
        ):
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return body.splitlines()[0].strip() if body.splitlines() else None

    def _extract_bmc_version(
        self,
        dut_dir: Path,
        firmware: List[Dict[str, Any]],
        bmc_os_text: Optional[str],
    ) -> Optional[str]:
        manager_version = self._extract_manager_firmware_version(dut_dir)
        if manager_version:
            return manager_version

        for item in firmware:
            name = " ".join(
                str(item.get(key, "")) for key in ("component", "name", "id")
            )
            if re.search(r"\bbmc\b", name, re.IGNORECASE) and item.get("version"):
                return str(item["version"])

        os_values = self._parse_key_value_text(self._command_output_body(bmc_os_text))
        return (
            os_values.get("IMAGE_VERSION")
            or os_values.get("VERSION_ID")
            or os_values.get("VERSION")
        )

    def _extract_manager_firmware_version(self, dut_dir: Path) -> Optional[str]:
        for pattern in (
            "**/Redfish_R14_manager_info*.json",
            "**/Redfish_R15_manager_expand_query*.json",
        ):
            for path in sorted(dut_dir.glob(pattern)):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                for item in self._walk_json_dicts(data):
                    version = item.get("FirmwareVersion")
                    if not version:
                        continue
                    name = " ".join(str(item.get(key, "")) for key in ("Id", "Name"))
                    if not name or re.search(r"\bbmc\b|manager", name, re.IGNORECASE):
                        return str(version)
        return None

    def _walk_json_dicts(self, value: Any):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from self._walk_json_dicts(child)
        elif isinstance(value, list):
            for child in value:
                yield from self._walk_json_dicts(child)

    def _extract_firmware_from_redfish(self, dut_dir: Path) -> List[Dict]:
        """Read firmware inventory from Redfish R20/R9/R8 files, matching legacy behavior."""
        firmware_items: List[Dict] = []

        r20_path = (
            dut_dir
            / "redfish"
            / "Redfish_R20_firmware_inventory_table"
            / "firmware_inventory_table.json"
        )
        r9_path = (
            dut_dir
            / "redfish"
            / "Redfish_R9_firmware_inventory_expand_query"
            / "Redfish_R9_firmware_inventory_expand_query.json"
        )
        r8_path = (
            dut_dir
            / "redfish"
            / "Redfish_R8_firmware_inventory"
            / "Redfish_R8_firmware_inventory.json"
        )

        try:
            if r20_path.exists():
                with open(r20_path, "r", encoding="utf-8") as f:
                    r20_data = json.load(f)
                if isinstance(r20_data, list):
                    for item in r20_data:
                        firmware_items.append(
                            {
                                "id": item.get("Id", ""),
                                "name": item.get("Name", item.get("Id", "")),
                                "version": item.get("Version", ""),
                            }
                        )
                    logger.debug("Read %d firmware items from R20", len(firmware_items))
                    return firmware_items

            if r9_path.exists():
                with open(r9_path, "r", encoding="utf-8") as f:
                    r9_data = json.load(f)
                members = (
                    r9_data.get("Members", []) if isinstance(r9_data, dict) else []
                )
                for member in members:
                    if isinstance(member, dict):
                        firmware_items.append(
                            {
                                "id": member.get("Id", ""),
                                "name": member.get("Name", member.get("Id", "")),
                                "version": member.get("Version", ""),
                            }
                        )
                logger.debug("Read %d firmware items from R9", len(firmware_items))
                return firmware_items

            if r8_path.exists():
                with open(r8_path, "r", encoding="utf-8") as f:
                    r8_data = json.load(f)
                members = (
                    r8_data.get("Members", []) if isinstance(r8_data, dict) else []
                )
                for member in members:
                    if isinstance(member, dict):
                        odata_id = member.get("@odata.id", "")
                        fw_id = odata_id.split("/")[-1] if odata_id else ""
                        firmware_items.append(
                            {
                                "id": fw_id,
                                "name": fw_id,
                                "version": "",
                            }
                        )
                logger.debug("Read %d firmware items from R8", len(firmware_items))
                return firmware_items

        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Error reading firmware data in %s: %s", dut_dir, e)

        return firmware_items

    def _read_dependency_check(self, dut_dir: Path, dut_id: str) -> Optional[Dict]:
        """Read dependency check data from .metadata/dependency_check.json.

        Structure: {"collectors": {"R1": {"name": "...", "dependencies": [...]}, ...}}
        """
        for metadata_name in (".metadata", "metadata"):
            dep_path = dut_dir / metadata_name / "dependency_check.json"
            if dep_path.exists():
                break
        else:
            return None

        try:
            with open(dep_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "Failed to read dependency_check.json for DUT %s: %s", dut_id, e
            )
            return None

        collectors_data = data.get("collectors", {}) if isinstance(data, dict) else {}
        if not isinstance(collectors_data, dict) or not collectors_data:
            return None

        collectors = []
        for collector_id, cinfo in collectors_data.items():
            if not isinstance(cinfo, dict):
                continue
            deps = cinfo.get("dependencies", [])
            collectors.append(
                {
                    "collector_id": collector_id,
                    "name": cinfo.get("name", collector_id),
                    "dependencies": deps if isinstance(deps, list) else [],
                }
            )

        if collectors:
            logger.debug(
                "Read %d dependency checks for DUT %s", len(collectors), dut_id
            )
        return {"dut_id": dut_id, "collectors": collectors} if collectors else None

    def _get_dut_execution_time(self, metadata_dir: Path, dut_dir: Path) -> float:
        """Get execution time for a DUT from timing.json, metadata.json, or summary report."""
        for metadata_name in (".metadata", "metadata"):
            timing_path = dut_dir / metadata_name / "timing.json"
            if not timing_path.exists():
                continue
            try:
                with open(timing_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                overall = data.get("overall", {}) if isinstance(data, dict) else {}
                if isinstance(overall, dict) and overall:
                    return float(
                        overall.get(
                            "wall_clock_duration_seconds",
                            overall.get("duration_seconds", 0),
                        )
                        or 0
                    )
                return float(data.get("total_duration", data.get("duration", 0)) or 0)
            except (json.JSONDecodeError, OSError, TypeError):
                pass

        summary_path = dut_dir / "Execution_Summary_Report.txt"
        if summary_path.exists():
            try:
                text = summary_path.read_text(encoding="utf-8")
                match = re.search(r"Log collection took (\d+\.?\d*) seconds", text)
                if match:
                    return float(match.group(1))
            except OSError:
                pass

        return 0.0

    def _get_baseboard(self, dut_dir: Path) -> str:
        """Get baseboard from DUT config."""
        return self._read_dut_config_field(dut_dir, "baseboard", "")

    def _get_node_type(self, dut_dir: Path) -> str:
        """Get node type from DUT config."""
        return self._read_dut_config_field(dut_dir, "NodeType", "Compute")

    def _get_bmc_ip(self, dut_dir: Path) -> str:
        """Get BMC IP from DUT config."""
        return self._read_dut_config_field(dut_dir, "BMC_IP", "")

    def _read_dut_config_field(self, dut_dir: Path, field: str, default: str) -> str:
        """Read a field from the DUT's dut_config.json."""
        config_path = dut_dir / "dut_config.json"
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return str(data.get(field, default))
            except (json.JSONDecodeError, OSError):
                pass
        return default

    def _calculate_dir_size(self, directory: Path) -> int:
        """Calculate total size of files in a directory."""
        total = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for f in files:
                try:
                    total += (Path(root) / f).stat().st_size
                except OSError:
                    pass
        return total

    def _compute_summary(self, manifest: Dict) -> Dict:
        """Compute collection summary from manifest data."""
        status_counts = {
            "success": 0,
            "error": 0,
            "partial": 0,
            "skipped": 0,
            "not_ran": 0,
        }
        total_log_size = 0
        total_executed = 0

        for dut in manifest.get("duts", []):
            summary = dut.get("status_summary", {})
            for key in status_counts:
                status_counts[key] += summary.get(key, 0)
            total_log_size += dut.get("log_size", 0)
            total_executed += sum(
                summary.get(k, 0) for k in ("success", "error", "partial")
            )

        total_to_run = total_executed + status_counts.get("skipped", 0)
        collection_pct = (
            (total_executed / total_to_run * 100) if total_to_run > 0 else 0
        )

        return {
            "total_duts": len(manifest.get("duts", [])),
            "total_collectors_executed": total_executed,
            "total_collectors_in_catalog": len(manifest.get("collector_catalog", [])),
            "total_collectors_filtered_out": 0,
            "total_log_size": total_log_size,
            "total_runtime": manifest.get("timing", {}).get("total_duration", 0),
            "overall_collection_pct": round(collection_pct, 1),
            "status_counts": status_counts,
        }

    def _copy_spa_assets(self, report_dir: Path) -> None:
        """Copy SPA dist files to the report directory."""
        import os
        import shutil
        import stat

        if not self.spa_dist_dir or not self.spa_dist_dir.exists():
            return
        for item in self.spa_dist_dir.iterdir():
            dest = report_dir / item.name
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        for root, dirs, files in os.walk(report_dir):
            for d in dirs:
                p = os.path.join(root, d)
                os.chmod(
                    p,
                    stat.S_IRWXU
                    | stat.S_IRGRP
                    | stat.S_IXGRP
                    | stat.S_IROTH
                    | stat.S_IXOTH,
                )
            for f in files:
                p = os.path.join(root, f)
                os.chmod(p, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    def _embed_manifest(self, index_html: Path, manifest_json: str) -> None:
        """Inject manifest JSON into index.html as a script tag.

        Escapes '</' as '<\\/' to prevent XSS via script tag injection.

        Targets the explicit ``__NVDEBUG_MANIFEST_PLACEHOLDER__`` HTML comment
        rather than ``</head>`` because the single-file SPA bundle embeds Vue
        template strings that contain ``</head>`` / ``</body>`` literals inside
        inlined JavaScript, which a naive replace would corrupt.
        """
        safe_json = manifest_json.replace("</", r"<\/").replace("<!--", r"<\!--")
        html = index_html.read_text(encoding="utf-8")
        script_tag = f"<script>window.__MANIFEST__ = {safe_json};</script>"
        placeholder = "<!-- __NVDEBUG_MANIFEST_PLACEHOLDER__ -->"
        if placeholder in html:
            html = html.replace(placeholder, script_tag, 1)
        else:
            # Fallback for older SPA bundles without the placeholder. Inject
            # before the FIRST top-level </head>, which in non-single-file
            # builds is always the real document head closer.
            if "</head>" in html:
                html = html.replace("</head>", f"{script_tag}\n</head>", 1)
            elif "</body>" in html:
                html = html.replace("</body>", f"{script_tag}\n</body>", 1)
            else:
                logger.warning(
                    "Could not embed manifest: no placeholder or </head>/</body> found in %s",
                    index_html,
                )
                return
        index_html.write_text(html, encoding="utf-8")
