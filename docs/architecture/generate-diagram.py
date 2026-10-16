#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "markdown-it-py>=4.2,<5",
#   "pyyaml>=6,<7",
# ]
# ///

"""Validate an architecture model and export layout-backed JSON for the site.

Pass --d2 DIR to retain the chosen d2 sources, or --check to validate without d2.
Service links are resolved from service.datadog.yaml files in this repository.
Adapted from domains/metrics/docs/architecture/generate-diagram.py in dd-source.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import math
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from itertools import pairwise
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import yaml
from markdown_it import MarkdownIt
from markdown_it.token import Token

SCRIPT_DIR = Path(__file__).resolve().parent
MODEL_PATH = SCRIPT_DIR / "model.yaml"
EXPORT_FILES = (
    "main.tsx",
    "App.tsx",
    "Diagram.tsx",
    "model.ts",
    "model.unit.ts",
    "architecture.less",
    "rum.ts",
    "rum.unit.ts",
    "types.ts",
)
SVG_NS = "http://www.w3.org/2000/svg"
FA_STEP_COUNTER_MAX = 2
ET.register_namespace("", SVG_NS)


def repo_root() -> Path:
    """The git repository this directory is in; service.datadog.yaml files are searched there."""
    result = subprocess.run(
        ["git", "-C", str(SCRIPT_DIR), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    return Path(result.stdout.strip()) if result.returncode == 0 else SCRIPT_DIR


REPO_ROOT = repo_root()
# set from model.yaml's site block by load_model()
MARKDOWN_PATH = SCRIPT_DIR / "architecture.md"
SOURCE_REPOSITORIES: dict[str, str] = {}

WIKI_SKIP = re.compile(r"team|game ?day|runbook|operation|deployment", re.IGNORECASE)
WIKI_SPACE = re.compile(r"/wiki/spaces/[^/]+/?(overview.*)?$", re.IGNORECASE)
WIKI_NAMES = ["service documentation", "documentation", "wiki", "overview"]

MARKDOWN = MarkdownIt("commonmark", {"html": False}).enable("table")
ANNOTATIONS = MarkdownIt("commonmark").enable("table")

KINDS = {"call", "read", "traffic"}
SHAPES = {"service", "external", "store", "object", "workload"}


class DiagramError(Exception):
    pass


def open_in_new_tab(self, tokens, idx, options, env):
    safe_url(tokens[idx].attrGet("href"), "Markdown link")
    tokens[idx].attrSet("target", "_blank")
    tokens[idx].attrSet("rel", "noopener")
    return self.renderToken(tokens, idx, options, env)


MARKDOWN.add_render_rule("link_open", open_in_new_tab)


def safe_url(value: str | None, where: str, https_only: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(c) < 32 or c == "\\" for c in value)
    ):
        raise DiagramError(f"{where}: unsafe URL {value!r}")
    parsed = urlsplit(value)
    if (
        parsed.scheme == "https"
        and parsed.netloc
        and not parsed.username
        and not parsed.password
    ):
        return value
    if (
        not https_only
        and not parsed.scheme
        and not parsed.netloc
        and not value.startswith("//")
        and (value.startswith("#") or not value.startswith("/"))
    ):
        return value
    raise DiagramError(
        f"{where}: URL must be HTTPS, a fragment or a relative path: {value!r}"
    )


def safe_links(links: dict[str, str], where: str) -> dict[str, str]:
    for key, value in links.items():
        safe_url(value, f"{where}.{key}", https_only=True)
    return links


def render_markdown(source: str) -> str:
    # markdown-it drops invalid links; reject their authored destinations as well.
    for target in re.findall(r"\]\(\s*([^\s)]+)", source):
        safe_url(html.unescape(target.strip("<>")), "Markdown link")
    for match in re.finditer(
        r"^\s{0,3}\[[^\]\n]+\]:[ \t]*(?:<([^>\n]+)>|([^\s]+))",
        source,
        re.MULTILINE,
    ):
        safe_url(html.unescape(match.group(1) or match.group(2)), "Markdown reference")
    env: dict[str, Any] = {}
    tokens = MARKDOWN.parse(source, env)
    for reference in env.get("references", {}).values():
        safe_url(reference["href"], "Markdown reference")

    def check_links(token: Token) -> None:
        if token.type in {"link_open", "image"}:
            safe_url(
                token.attrGet("href" if token.type == "link_open" else "src"),
                "Markdown link or image",
            )
        for child in token.children or []:
            check_links(child)

    for token in tokens:
        check_links(token)
    return MARKDOWN.renderer.render(tokens, MARKDOWN.options, env).strip()


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


# ------------------------------------------------------------------------ model


def load_model() -> dict[str, Any]:
    global MARKDOWN_PATH, SOURCE_REPOSITORIES
    model = yaml.safe_load(MODEL_PATH.read_text())
    if not isinstance(model, dict):
        raise DiagramError("model.yaml: expected a mapping")
    for key in ("frames", "nodes", "views", "edges", "flows", "kinds", "shapes"):
        if not isinstance(
            model.get(key), (list if key in ("views", "edges") else dict)
        ):
            raise DiagramError(
                f"model.yaml: {key} must be a {'list' if key in ('views', 'edges') else 'mapping'}"
            )
    frames, nodes, views = model["frames"], model["nodes"], model["views"]
    errors: list[str] = []
    for index, view in enumerate(views):
        if not isinstance(view, dict) or not all(
            isinstance(view.get(k), str) and view[k] for k in ("id", "title", "group")
        ):
            errors.append(f"views[{index}]: id, title and group are required strings")
    if errors:
        raise DiagramError("model.yaml:\n  " + "\n  ".join(errors))
    view_ids = {v["id"] for v in views}
    if len(view_ids) != len(views):
        errors.append("views: duplicate id")

    site = model.get("site") or {}
    if not isinstance(site, dict):
        raise DiagramError("model.yaml: site must be a mapping")
    for key in ("title", "markdown", "app"):
        if not site.get(key):
            errors.append(f"site.{key} is required")
    if not isinstance(site.get("app"), str) or not re.fullmatch(
        r"[a-z][a-z0-9-]*", site["app"]
    ):
        errors.append("site.app must be a lowercase, hyphenated static-app name")
    repositories = site.get("source_repositories", {})
    if not isinstance(repositories, dict):
        raise DiagramError("site.source_repositories must be a mapping")
    SOURCE_REPOSITORIES = {}
    for alias, url in repositories.items():
        if not isinstance(alias, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", alias):
            errors.append(
                "site.source_repositories aliases must be lowercase, hyphenated names"
            )
        elif not isinstance(url, str) or not repo_base({"source_url": url}):
            errors.append(
                f"site.source_repositories.{alias} must be an HTTPS GitHub tree/blob URL"
            )
        else:
            safe_url(url, f"site.source_repositories.{alias}", https_only=True)
            SOURCE_REPOSITORIES[alias] = repo_base({"source_url": url})
    rum = site.get("rum")
    if rum is not None:
        if not isinstance(rum, dict):
            raise DiagramError("model.yaml: site.rum must be a mapping")
        for key in ("application_id", "client_token", "service"):
            if not rum.get(key):
                errors.append(f"site.rum.{key} is required when site.rum is set")
    MARKDOWN_PATH = SCRIPT_DIR / site.get("markdown", "architecture.md")
    theme = site.get("theme", {"default": "system"})
    if (
        not isinstance(theme, dict)
        or not isinstance(theme.get("default"), str)
        or theme["default"] not in {"system", "light", "dark"}
        or set(theme) != {"default"}
    ):
        errors.append("site.theme.default must be system, light or dark")
    else:
        site["theme"] = theme
    if not isinstance(site.get("source_url"), str) or not repo_base(site):
        errors.append(
            "site.source_url must be an HTTPS GitHub tree/blob URL for source links"
        )
    else:
        safe_url(site["source_url"], "site.source_url", https_only=True)
    for fid, flow in model["flows"].items():
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]*", str(fid))
            or not isinstance(flow, dict)
            or not isinstance(flow.get("label"), str)
            or not flow["label"]
        ):
            errors.append(f"flows.{fid}: invalid id or missing label")
            continue
        if set(flow) != {"label", "color", "dark_color"}:
            errors.append(f"flows.{fid}: expected only label, color and dark_color")
        for color in ("color", "dark_color"):
            if not isinstance(flow.get(color), str) or not re.fullmatch(
                r"#[0-9a-fA-F]{6}", flow[color]
            ):
                errors.append(f"flows.{fid}.{color} must be a six-digit hex color")

    for oid, owner in (model.get("owners") or {}).items():
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]*", str(oid))
            or not isinstance(owner, dict)
            or not isinstance(owner.get("label"), str)
            or not owner["label"]
        ):
            errors.append(f"owners.{oid}: invalid id or missing label")
            continue
        if set(owner) != {"label", "color", "dark_color"}:
            errors.append(
                f"owners.{oid}: expected only label, color and dark_color"
            )
        for color in ("color", "dark_color"):
            if not isinstance(owner.get(color), str) or not re.fullmatch(
                r"#[0-9a-fA-F]{6}", owner[color]
            ):
                errors.append(f"owners.{oid}.{color} must be a six-digit hex color")

    # an unquoted comma in a {flow: mapping} silently starts a new, empty key
    def empty_keys(value: Any, where: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if child is None and f"{where}.{key}" != "model.site.rum":
                    errors.append(
                        f"{where}.{key} is empty; quote a value that contains a comma"
                    )
                empty_keys(child, f"{where}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                empty_keys(child, f"{where}[{index}]")

    empty_keys(model, "model")

    for fid, frame in frames.items():
        if frame.get("kind") and frame["kind"] not in FRAME_STYLES:
            errors.append(f"frame {fid}: unknown kind {frame['kind']}")
        if frame.get("kind") and frame["kind"] not in (model.get("frame_kinds") or {}):
            errors.append(
                f"frame {fid}: kind {frame['kind']} has no frame_kinds entry for the legend"
            )
        if frame.get("parent") and frame["parent"] not in frames:
            errors.append(f"frame {fid}: unknown parent {frame['parent']}")
        if frame.get("owner") and frame["owner"] not in (model.get("owners") or {}):
            errors.append(f"frame {fid}: unknown owner {frame['owner']}")
        if fid in nodes:
            errors.append(f"{fid} is both a frame and a box")
    for nid, node in nodes.items():
        node.setdefault("shape", "service")
        if node["shape"] not in SHAPES:
            errors.append(f"box {nid}: unknown shape {node['shape']}")
        if node.get("frame") and node["frame"] not in frames:
            errors.append(f"box {nid}: unknown frame {node['frame']}")
        if node.get("owner") and node["owner"] not in (model.get("owners") or {}):
            errors.append(f"box {nid}: unknown owner {node['owner']}")
        # the page draws a label's second line as a smaller, grey subtitle
        if re.search(r"-\n", node["label"]):
            errors.append(
                f"box {nid}: its label breaks a word; a second line is drawn as a subtitle"
            )

    seen: set[tuple[str, str]] = set()
    for edge in model["edges"]:
        where = f"edge {edge.get('from')} -> {edge.get('to')}"
        for end in ("from", "to"):
            if edge[end] not in nodes and edge[end] not in frames:
                errors.append(f"{where}: unknown {end} {edge[end]}")
        if (edge["from"], edge["to"]) in seen:
            errors.append(f"{where}: duplicate; use per-view labels instead")
        seen.add((edge["from"], edge["to"]))
        if edge["kind"] not in KINDS:
            errors.append(f"{where}: unknown kind {edge['kind']}")
        for flow in [edge["flow"], *(edge.get("flows") or {}).values()]:
            if flow not in model["flows"]:
                errors.append(f"{where}: unknown flow {flow}")
        for view in [
            *edge["views"],
            *(edge.get("labels") or {}),
            *(edge.get("flows") or {}),
        ]:
            if view not in view_ids:
                errors.append(f"{where}: unknown view {view}")
            elif next(v for v in views if v["id"] == view).get("category") == "flow":
                errors.append(
                    f"{where}: flow view {view} must use steps, not edge membership/overrides"
                )

    pairs = {(edge["from"], edge["to"]) for edge in model["edges"]}
    for view in views:
        vid = view["id"]
        unexpected = set(view) - {
            "id",
            "title",
            "category",
            "group",
            "layout",
            "scenario",
            "steps",
        }
        if unexpected:
            errors.append(f"view {vid}: unknown fields {sorted(unexpected)}")
        category = view.get("category")
        if category not in ("architecture", "flow"):
            errors.append(f"view {vid}: category is required (architecture or flow)")
        if category == "architecture" and ("steps" in view or "scenario" in view):
            errors.append(f"view {vid}: architecture cannot have scenario or steps")
        if category == "flow":
            scenario = view.get("scenario")
            if not isinstance(scenario, dict):
                errors.append(f"view {vid}: scenario is required")
                scenario = {}
            if set(scenario) - {
                "actor",
                "trigger",
                "preconditions",
                "end_state",
                "limitations",
                "architecture_view",
            }:
                errors.append(f"view {vid}: unknown scenario fields")
            for key in ("actor", "trigger", "end_state", "architecture_view"):
                if not isinstance(scenario.get(key), str) or not scenario[key]:
                    errors.append(f"view {vid}: scenario.{key} is required")
            for key in ("preconditions", "limitations"):
                if not isinstance(scenario.get(key), list) or any(
                    not isinstance(x, str) or not x for x in scenario[key]
                ):
                    errors.append(
                        f"view {vid}: scenario.{key} must be a list of strings"
                    )
            if (
                isinstance(scenario.get("actor"), str)
                and scenario["actor"] not in nodes
            ):
                errors.append(f"view {vid}: scenario.actor must reference a box")
            if not any(
                v["id"] == scenario.get("architecture_view")
                and v.get("category") == "architecture"
                for v in views
            ):
                errors.append(
                    f"view {vid}: scenario.architecture_view must reference an architecture view"
                )
            steps = view.get("steps")
            if not isinstance(steps, list) or not 3 <= len(steps) <= 8:
                errors.append(f"view {vid}: steps must contain 3-8 ordered entries")
                steps = []
            for number, step in enumerate(steps, 1):
                where = f"view {vid} step {number}"
                if not isinstance(step, dict):
                    errors.append(f"{where}: must be a mapping")
                    continue
                if set(step) - {
                    "from",
                    "to",
                    "label",
                    "verification",
                    "sources",
                    "note",
                }:
                    errors.append(f"{where}: unknown step fields")
                if not all(isinstance(step.get(end), str) for end in ("from", "to")):
                    errors.append(f"{where}: from and to must be box or frame IDs")
                elif (step["from"], step["to"]) not in pairs:
                    errors.append(
                        f"{where}: no base edge for {step['from']} -> {step['to']}"
                    )
                if not isinstance(step.get("label"), str) or not step["label"]:
                    errors.append(f"{where}: label is required")
                verification = step.get("verification")
                if verification not in ("code", "configuration", "unverified"):
                    errors.append(
                        f"{where}: verification must be code, configuration or unverified"
                    )
                sources = step.get("sources")
                if not isinstance(sources, list):
                    errors.append(f"{where}: sources must be a list")
                    sources = []
                if verification in ("code", "configuration") and not sources:
                    errors.append(
                        f"{where}: {verification} requires at least one source"
                    )
                if "note" in step and (
                    not isinstance(step["note"], str) or not step["note"].strip()
                ):
                    errors.append(f"{where}: note must be nonempty text")
                if verification == "unverified" and not step.get("note"):
                    errors.append(f"{where}: unverified requires a note")
                for source in sources:
                    if (
                        not isinstance(source, dict)
                        or not isinstance(source.get("path"), str)
                        or not isinstance(source.get("symbol"), str)
                        or not source["symbol"]
                    ):
                        errors.append(f"{where}: source requires path and symbol")
                        continue
                    if set(source) - {"path", "symbol", "lines"}:
                        errors.append(f"{where}: unknown source fields")
                    path = source["path"]
                    if (
                        Path(path).is_absolute()
                        or not (REPO_ROOT / path).is_file()
                        or not (REPO_ROOT / path)
                        .resolve()
                        .is_relative_to(REPO_ROOT.resolve())
                    ):
                        errors.append(
                            f"{where}: source path {path!r} must be an existing repository file"
                        )
                    lines = source.get("lines")
                    if lines is not None and (
                        not isinstance(lines, list)
                        or len(lines) != 2
                        or any(type(n) is not int or n < 1 for n in lines)
                        or lines[0] > lines[1]
                    ):
                        errors.append(
                            f"{where}: source.lines must be [positive start, end]"
                        )
            if (
                steps
                and isinstance(steps[0], dict)
                and isinstance(scenario.get("actor"), str)
                and scenario["actor"] not in (steps[0].get("from"), steps[0].get("to"))
            ):
                errors.append(
                    f"view {vid}: scenario.actor must participate in the first step"
                )

        spec = view.get("layout") or {}
        if "align_columns" in spec and type(spec["align_columns"]) is not bool:
            errors.append(f"view {vid}: layout.align_columns must be boolean")
        if "route" in spec and spec["route"] != "orthogonal":
            errors.append(f"view {vid}: layout.route must be orthogonal")
        if (spec.get("align_columns") or spec.get("route")) and (
            category != "architecture"
            or spec.get("engine") != "elk"
            or spec.get("direction", "right") != "right"
        ):
            errors.append(
                f"view {vid}: column alignment/routing requires an ELK rightward architecture view"
            )
        if spec.get("engine", "tala") not in {"tala", "elk"}:
            errors.append(f"view {view['id']}: layout.engine must be tala or elk")
        if spec.get("direction", "right") not in {"right", "down", "left", "up"}:
            errors.append(f"view {view['id']}: unknown layout.direction")
        if "seed" in spec and spec["seed"] not in SEEDS:
            errors.append(f"view {view['id']}: layout.seed must be 1-16")

    drawn = {e[end] for e in model["edges"] for end in ("from", "to")}
    errors += [f"box {nid} has no edges" for nid in nodes if nid not in drawn]
    if errors:
        raise DiagramError("model.yaml:\n  " + "\n  ".join(errors))
    return model


def view_edges(model: dict[str, Any], view: str) -> list[dict[str, Any]]:
    """The edges a view draws, with its label and flow resolved."""
    spec = next(v for v in model["views"] if v["id"] == view)
    if spec["category"] == "flow":
        registry = {(edge["from"], edge["to"]): edge for edge in model["edges"]}
        return [
            {
                **registry[(step["from"], step["to"])],
                "label": step["label"],
                "number": number,
            }
            for number, step in enumerate(spec["steps"], 1)
        ]
    out = []
    for edge in model["edges"]:
        if view == "complete":
            if edge.get("complete", True) is False:
                continue
        elif view not in edge["views"]:
            continue
        out.append(
            {
                **edge,
                "label": (edge.get("labels") or {}).get(view, edge.get("label", "")),
                "flow": (edge.get("flows") or {}).get(view, edge["flow"]),
            }
        )
    return out


# --------------------------------------------------------------------------- d2


def d2_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


# Frame paint is normalized by kind after d2 layout.
FRAME_STYLES = {
    # a datacenter or other hard boundary
    "boundary": 'stroke: "#868e96"; fill: transparent; stroke-dash: 0; stroke-width: 2',
    # one of several identical copies, such as a zone; drawn stacked
    "repeated": 'stroke: "#868e96"; fill: "#fcfcfc"; stroke-dash: 5; multiple: true',
    # a kind of cluster or other grouping
    "group": 'stroke: "#adb5bd"; fill: transparent; stroke-dash: 2',
    # a pod
    "pod": 'stroke: "#ced4da"; fill: "#f8f9fa"; stroke-dash: 0',
    # a component with parts, such as a controller and its managers
    "component": 'stroke: "#868e96"; fill: "#ffffff"; stroke-dash: 0',
}


def frame_kind(model: dict[str, Any], fid: str) -> str:
    """A frame's kind: its own, else boundary at the top level and group below it."""
    frame = model["frames"][fid]
    return frame.get("kind") or ("group" if frame.get("parent") else "boundary")


def frame_style(model: dict[str, Any], fid: str) -> str:
    style = FRAME_STYLES[frame_kind(model, fid)]
    return f"{{{style}; border-radius: 8; font-size: 15; bold: false}}"


def view_layout(model: dict[str, Any], view: str) -> tuple[str, str]:
    """Flow layouts use ELK by default; architecture keeps TALA seed scoring."""
    selected = next(v for v in model["views"] if v["id"] == view)
    spec = selected.get("layout") or {}
    default = "elk" if selected["category"] == "flow" and not spec else "tala"
    return spec.get("engine", default), spec.get("direction", "right")


def view_seeds(model: dict[str, Any], view: str) -> list[int]:
    """The TALA seeds to try: all of them, or the one the view pins. Other engines
    don't take a seed."""
    spec = next(v for v in model["views"] if v["id"] == view).get("layout") or {}
    if view_layout(model, view)[0] != "tala":
        return [1]
    return [spec["seed"]] if "seed" in spec else list(SEEDS)


def node_class(node: dict[str, Any]) -> str:
    """D2 class list for a box: its shape, plus an owner fill class when set."""
    shape = node["shape"]
    owner = node.get("owner")
    return f"[{shape}; owner-{owner}]" if owner else shape


def build_d2(
    model: dict[str, Any], view: str, node_widths: dict[str, float] | None = None
) -> str:
    engine, direction = view_layout(model, view)
    frames, nodes, flows = model["frames"], model["nodes"], model["flows"]
    edges = view_edges(model, view)

    def path(item: str) -> str:
        parts = [item]
        parent = (
            nodes[item].get("frame") if item in nodes else frames[item].get("parent")
        )
        while parent:
            parts.append(parent)
            parent = frames[parent].get("parent")
        return ".".join(reversed(parts))

    used_nodes = {e[end] for e in edges for end in ("from", "to") if e[end] in nodes}
    used_frames: set[str] = set()
    for item in used_nodes:
        parent = nodes[item].get("frame")
        while parent:
            used_frames.add(parent)
            parent = frames[parent].get("parent")
    # a frame an edge points at, with nothing of its own drawn inside, is drawn as a box
    boxed = {
        e[end] for e in edges for end in ("from", "to") if e[end] in frames
    } - used_frames
    for fid in boxed:
        parent = frames[fid].get("parent")
        while parent:
            used_frames.add(parent)
            parent = frames[parent].get("parent")

    lines = [
        f"vars: {{d2-config: {{layout-engine: {engine}; theme-id: 0; pad: 24; data: {{tala-seeds: [__SEED__]}}}}}}",
        f"direction: {direction}",
        "classes: {",
        '  service: {style: {stroke: "#343a40"; fill: "#ffffff"; border-radius: 6; font-size: 20}}',
        '  external: {style: {stroke: "#adb5bd"; fill: "#ffffff"; stroke-dash: 3; border-radius: 6; font-size: 20}}',
        '  store: {shape: cylinder; style: {stroke: "#343a40"; fill: "#fdeada"; font-size: 20}}',
        '  object: {shape: page; style: {stroke: "#868e96"; fill: "#ffffff"; font-size: 18}}',
        '  workload: {style: {stroke: "#495057"; fill: "#e9ecef"; border-radius: 6; font-size: 20}}',
        "  frame",
        "  kind-call",
        "  kind-read: {style.stroke-dash: 4}",
        "  kind-traffic: {style.stroke-width: 3}",
    ]
    for fid, flow in flows.items():
        lines.append(f'  flow-{fid}: {{style.stroke: "{flow["color"]}"}}')
    for oid, owner in (model.get("owners") or {}).items():
        lines.append(f'  owner-{oid}: {{style: {{fill: "{owner["color"]}"}}}}')
    lines.append("}")

    def emit_frame(fid: str, indent: str) -> None:
        frame = frames[fid]
        lines.append(f"{indent}{fid}: {d2_string(frame['label'])} {{")
        lines.append(f"{indent}  class: frame")
        lines.append(f"{indent}  style: {frame_style(model, fid)}")
        lines.append(f"{indent}  label.near: top-left")
        emit_children(fid, indent + "  ")
        lines.append(f"{indent}}}")

    def emit_children(parent: str | None, indent: str) -> None:
        for nid, node in nodes.items():
            if nid in used_nodes and node.get("frame") == parent:
                width = (
                    f"; width: {node_widths[nid]:g}"
                    if node_widths and nid in node_widths
                    else ""
                )
                lines.append(
                    f"{indent}{nid}: {d2_string(node['label'])} "
                    f"{{class: {node_class(node)}{width}}}"
                )
        for fid, frame in frames.items():
            if fid in boxed and frame.get("parent") == parent:
                shape = "workload" if frame_kind(model, fid) == "pod" else "service"
                lines.append(
                    f"{indent}{fid}: {d2_string(frame['label'])} {{class: {shape}}}"
                )
            elif fid in used_frames and frame.get("parent") == parent:
                emit_frame(fid, indent)

    emit_children(None, "")

    for edge in edges:
        # D2 must allocate the largest badge inside its edge-label box before layout.
        reserve = "MMMM" * FA_STEP_COUNTER_MAX
        label_text = (
            "\n".join(
                [
                    f"{edge['number']} {reserve}",
                    *([reserve] * (FA_STEP_COUNTER_MAX * 2 - 1)),
                    edge["label"],
                ]
            )
            if "number" in edge
            else edge["label"]
        )
        label = d2_string(label_text) if label_text else ""
        style = 'style: {font-size: 16; italic: false; font-color: "#5c6570"}'
        lines.append(
            f"{path(edge['from'])} -> {path(edge['to'])}: {label} "
            f"{{class: [kind-{edge['kind']}; flow-{edge['flow']}]; {style}}}"
        )
    return "\n".join(lines) + "\n"


SEEDS = range(1, 17)
ELK_SPACING = [
    "--elk-nodeNodeBetweenLayers",
    "40",
    "--elk-edgeNodeBetweenLayers",
    "15",
    "--elk-padding",
    "[top=36,left=16,bottom=16,right=16]",
]
TARGET_ASPECT = 1.6


def aligned_node_widths(model: dict[str, Any], svg: str) -> dict[str, float]:
    """Size nodes in each populated frame to its widest label after D2 measures it."""
    root = ET.fromstring(svg)
    ns = f"{{{SVG_NS}}}"
    widths: dict[str, float] = {}
    for group in root.iter(f"{ns}g"):
        classes = group.get("class", "").split()
        if not classes:
            continue
        try:
            node_id = (
                base64.b64decode(classes[0], validate=True).decode().split(".")[-1]
            )
        except (ValueError, UnicodeDecodeError):
            continue
        if node_id not in model["nodes"]:
            continue
        shape = group.find(f"{ns}g[@class='shape']")
        if shape is None:
            continue
        rect = shape.find(f"{ns}rect")
        if rect is not None:
            width = float(rect.get("width"))
        else:
            page = shape.find(f"{ns}path")
            if page is None:
                continue
            # D2's page shape is a path rather than a rect. Its M/L/C pairs and
            # horizontal H commands contain the x coordinates of both sides.
            d = page.get("d", "")
            x_values = [
                float(x) for x in re.findall(r"(?:[MLH]|C)\s*(-?\d+(?:\.\d+)?)", d)
            ]
            x_values += [
                float(x)
                for curve in re.findall(r"C\s*((?:-?\d+(?:\.\d+)?\s+){6})", d)
                for x in re.findall(r"-?\d+(?:\.\d+)?", curve)[2::2]
            ]
            if not x_values:
                continue
            width = max(x_values) - min(x_values)
        widths[node_id] = width

    widest = {
        frame: max(
            widths[nid] for nid in widths if model["nodes"][nid].get("frame") == frame
        )
        for frame in {model["nodes"][nid].get("frame") for nid in widths}
        if frame is not None
    }
    return {
        nid: widest[frame]
        for nid in widths
        if (frame := model["nodes"][nid].get("frame")) in widest
    }


def polylines(svg: str) -> list[list[tuple[float, float]]]:
    """The points of every edge path. Rounded corners add a few extra points; fine here."""
    lines = []
    for d in re.findall(r'<path d="([^"]+)"[^>]*class="connection', svg):
        if "Q" in d:
            # Our Q control points are the original right-angle corners. Ignore
            # curve tangencies when measuring crossings, slants and length.
            commands = re.findall(r"([MLQ])\s*(-?[\d.]+)\s+(-?[\d.]+)", d)
            points = [(float(x), float(y)) for _, x, y in commands]
            lines.append(
                [
                    points[0],
                    *[
                        points[i]
                        for i, (cmd, _, _) in enumerate(commands)
                        if cmd == "Q"
                    ],
                    points[-1],
                ]
            )
        else:
            nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", d)]
            lines.append(list(zip(nums[0::2], nums[1::2])))
    return lines


def crossings(svg: str) -> int:
    def crosses(a, b) -> bool:
        (x1, y1), (x2, y2) = a
        (x3, y3), (x4, y4) = b
        den = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4)
        if abs(den) < 1e-9:
            return False
        t = ((x1 - x3) * (y3 - y4) - (y1 - y3) * (x3 - x4)) / den
        u = -((x1 - x2) * (y1 - y3) - (y1 - y2) * (x1 - x3)) / den
        return 0.02 < t < 0.98 and 0.02 < u < 0.98

    segments = [list(pairwise(p)) for p in polylines(svg)]
    return sum(
        crosses(a, b)
        for i, first in enumerate(segments)
        for second in segments[i + 1 :]
        for a in first
        for b in second
    )


def overlaps(svg: str) -> int:
    """Pairs of edges that run along the same horizontal or vertical line for a while."""
    runs: list[tuple[int, str, float, float, float]] = []
    for index, line in enumerate(polylines(svg)):
        for (x1, y1), (x2, y2) in pairwise(line):
            if abs(y1 - y2) < 0.5 and abs(x1 - x2) > 12:
                runs.append((index, "h", y1, min(x1, x2), max(x1, x2)))
            elif abs(x1 - x2) < 0.5 and abs(y1 - y2) > 12:
                runs.append((index, "v", x1, min(y1, y2), max(y1, y2)))
    pairs = set()
    for i, (e1, o1, c1, lo1, hi1) in enumerate(runs):
        for e2, o2, c2, lo2, hi2 in runs[i + 1 :]:
            if (
                e1 != e2
                and o1 == o2
                and abs(c1 - c2) < 3
                and min(hi1, hi2) - max(lo1, lo2) > 24
            ):
                pairs.add((min(e1, e2), max(e1, e2)))
    return len(pairs)


def diagonals(svg: str) -> int:
    """Edge segments that are neither horizontal nor vertical. Every other edge on a board
    is drawn at right angles, so a slanted one reads as a mistake. Rounded corners add
    only short slanted segments, which the length threshold ignores."""
    return sum(
        abs(x1 - x2) > 3 and abs(y1 - y2) > 3 and math.dist((x1, y1), (x2, y2)) > 30
        for line in polylines(svg)
        for (x1, y1), (x2, y2) in pairwise(line)
    )


def jogs(svg: str) -> int:
    """Bends beyond the first in each edge: a zigzag where one corner, or none, would do.
    d2 draws each corner as a short curve."""
    return sum(
        max(0, len(re.findall(r"[SCQ]", d)) - 1)
        for d in re.findall(r'<path d="([^"]+)"[^>]*class="connection', svg)
    )


def layout_metrics(svg: str) -> dict[str, float]:
    match = re.search(r'viewBox="[-\d.]+ [-\d.]+ ([\d.]+) ([\d.]+)"', svg)
    width, height = (
        (float(match.group(1)), float(match.group(2))) if match else (1.0, 1.0)
    )
    return {
        "crossings": crossings(svg) + overlaps(svg),
        "diagonals": diagonals(svg),
        "jogs": jogs(svg),
        "area": width * height,
        "length": sum(
            math.dist(a, b) for line in polylines(svg) for a, b in pairwise(line)
        )
        or 1.0,
        "shape": abs(math.log(width / height / TARGET_ASPECT)),
    }


def pick_layout(candidates: list[tuple[int, str]]) -> tuple[int, str, dict[str, float]]:
    """(seed, svg, metrics) of the best of one view's layouts. Each measure is taken
    relative to the best candidate, so no one measure swamps the others: a crossing, or two
    edges drawn on top of each other, costs as much as a third more canvas, and so does
    a zigzag. A slanted edge all but rules a layout out."""
    measured = [(seed, svg, layout_metrics(svg)) for seed, svg in candidates]
    least = {
        key: min(m[key] for _, _, m in measured)
        for key in ("crossings", "area", "length", "jogs")
    }

    def score(item: tuple[int, str, dict[str, float]]) -> tuple[float, int]:
        seed, _, m = item
        return (
            10 * m["diagonals"]
            + m["crossings"] / (least["crossings"] + 2)
            + 1.5 * m["area"] / least["area"]
            + m["length"] / least["length"]
            + m["jogs"] / (least["jogs"] + 2)
            + 2 * m["shape"],
            seed,
        )

    return min(measured, key=score)


def render_boards(model: dict[str, Any], keep_d2: Path | None) -> dict[str, str]:
    """Board id -> SVG. TALA's layout depends on its seed, so each view is laid out with
    every seed and the layout with the fewest crossings wins."""
    d2 = shutil.which("d2")
    if not d2:
        raise DiagramError("d2 not found; install d2 v0.9.0 or later")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        sources = {v["id"]: build_d2(model, v["id"]) for v in model["views"]}

        def one(job: tuple[str, int]) -> tuple[str, int, str]:
            view, seed = job
            src = work / f"{view}-{seed}.d2"
            out = work / f"{view}-{seed}.svg"
            # ELK's default spacing leaves layered views far wider than they need to be
            spacing = ELK_SPACING if view_layout(model, view)[0] == "elk" else []

            def render(source: str) -> str:
                src.write_text(source.replace("__SEED__", str(seed)))
                result = subprocess.run(
                    [d2, "--omit-version", *spacing, str(src), str(out)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    raise DiagramError(
                        f"d2 failed on view {view}:\n{result.stderr.strip()}"
                    )
                return out.read_text()

            svg = render(sources[view])
            spec = next(v for v in model["views"] if v["id"] == view).get("layout", {})
            if spec.get("align_columns") or spec.get("route") == "orthogonal":
                sources[view] = build_d2(model, view, aligned_node_widths(model, svg))
                svg = render(sources[view])
            return view, seed, svg

        with ThreadPoolExecutor() as pool:
            # only TALA's layout depends on a seed
            jobs = [(v, s) for v in sources for s in view_seeds(model, v)]
            layouts = list(pool.map(one, jobs))
    by_view: dict[str, list[tuple[int, str]]] = {}
    for view, seed, svg in layouts:
        by_view.setdefault(view, []).append((seed, svg))
    boards = {}
    for view, candidates in by_view.items():
        seed, svg, metrics = pick_layout(candidates)
        if keep_d2:
            keep_d2.mkdir(parents=True, exist_ok=True)
            # with the chosen seed, so the file reproduces this layout
            (keep_d2 / f"{view}.d2").write_text(
                sources[view].replace("__SEED__", str(seed))
            )
        print(
            f"  {view}: seed {seed}, {metrics['crossings']} crossings or overlaps,"
            f" {metrics['jogs']} zigzags, {metrics['diagonals']} slanted edges",
            file=sys.stderr,
        )
        boards[view] = svg
    return boards


def drawn_ids(model: dict[str, Any], edges: list[dict[str, Any]]) -> set[str]:
    nodes, frames = model["nodes"], model["frames"]
    present = {e[end] for e in edges for end in ("from", "to")}
    result = set(present)
    for item in present:
        parent = (
            nodes[item].get("frame") if item in nodes else frames[item].get("parent")
        )
        while parent:
            result.add(parent)
            parent = frames[parent].get("parent")
    return result


def d2_path(model: dict[str, Any], item: str) -> str:
    parts = [item]
    parent = (
        model["nodes"][item].get("frame")
        if item in model["nodes"]
        else model["frames"][item].get("parent")
    )
    while parent:
        parts.append(parent)
        parent = model["frames"][parent].get("parent")
    return ".".join(reversed(parts))


def paint(element: ET.Element, attribute: str, role: str, fallback: str) -> None:
    element.set(attribute, f"var(--fa-{role}, {fallback})")


def node_box(group: ET.Element) -> tuple[float, float, float, float]:
    """Bounds of a D2 node's rectangle or page outline (left, top, right, bottom)."""
    ns = f"{{{SVG_NS}}}"
    shape = group.find(f"{ns}g[@class='shape']")
    if shape is None:
        raise DiagramError(f"node {group.get('data-node')}: no shape")
    rect = shape.find(f"{ns}rect")
    if rect is not None:
        x, y, w, h = (float(rect.get(key)) for key in ("x", "y", "width", "height"))
        return x, y, x + w, y + h
    path = shape.find(f"{ns}path")
    if path is None:
        raise DiagramError(f"node {group.get('data-node')}: no outline")
    xs, ys = [], []
    for command, arguments in re.findall(r"([MLCHV])\s*([\d.\s-]+)", path.get("d", "")):
        values = [float(value) for value in arguments.split()]
        if command == "H":
            xs.extend(values)
        elif command == "V":
            ys.extend(values)
        else:
            xs.extend(values[::2])
            ys.extend(values[1::2])
    if not xs or not ys:
        raise DiagramError(f"node {group.get('data-node')}: invalid outline")
    return min(xs), min(ys), max(xs), max(ys)


def rounded_orthogonal_path(points: list[tuple[float, float]]) -> str:
    """Round each orthogonal corner, leaving the first and last legs tangent."""
    x, y = points[0]
    commands = [f"M {x:g} {y:g}"]
    for before, corner, after in zip(points, points[1:], points[2:]):
        incoming = (corner[0] - before[0], corner[1] - before[1])
        outgoing = (after[0] - corner[0], after[1] - corner[1])
        radius = min(
            8,
            (abs(incoming[0]) + abs(incoming[1])) / 2,
            (abs(outgoing[0]) + abs(outgoing[1])) / 2,
        )
        if not radius:
            continue
        entry = (
            corner[0] - math.copysign(radius, incoming[0])
            if incoming[0]
            else corner[0],
            corner[1] - math.copysign(radius, incoming[1])
            if incoming[1]
            else corner[1],
        )
        exit = (
            corner[0] + math.copysign(radius, outgoing[0])
            if outgoing[0]
            else corner[0],
            corner[1] + math.copysign(radius, outgoing[1])
            if outgoing[1]
            else corner[1],
        )
        commands.extend(
            (
                f"L {entry[0]:g} {entry[1]:g}",
                f"Q {corner[0]:g} {corner[1]:g} {exit[0]:g} {exit[1]:g}",
            )
        )
    x, y = points[-1]
    commands.append(f"L {x:g} {y:g}")
    return " ".join(commands)


def draw_column_lanes(
    lanes: list[tuple[str, str, ET.Element]],
    ports: dict[tuple[str, str], list[float]],
    boxes: dict[str, tuple[float, float, float, float]],
    left: float,
    right: float,
) -> None:
    for index, (source, target, path) in enumerate(lanes):
        start_y, end_y = ports[(source, target)]
        lane_x = left + (right - left) * (index + 1) / (len(lanes) + 1)
        path.set(
            "d",
            rounded_orthogonal_path(
                [
                    (boxes[source][2], start_y),
                    (lane_x, start_y),
                    (lane_x, end_y),
                    (boxes[target][0] - 4, end_y),
                ]
            ),
        )


def route_adjacent_columns(root: ET.Element) -> None:
    """Route neighboring ELK columns after layout, preserving D2's edge markers and paint."""
    ns = f"{{{SVG_NS}}}"
    boxes = {
        group.get("data-node"): node_box(group)
        for group in root.iter(f"{ns}g")
        if group.get("data-node") and "frame" not in group.get("class", "").split()
    }
    columns = sorted({box[0] for box in boxes.values()})
    column = {node: columns.index(box[0]) for node, box in boxes.items()}
    gaps: dict[int, list[tuple[str, str, ET.Element]]] = {}
    for group in root.iter(f"{ns}g"):
        source, target = group.get("data-from"), group.get("data-to")
        if source not in column or target not in column:
            continue
        start = column[source]
        if column[target] != start + 1:
            continue
        path = next(
            (
                path
                for path in group.iter(f"{ns}path")
                if "connection" in path.get("class", "").split()
            ),
            None,
        )
        if path is None:
            raise DiagramError(f"edge {source}->{target}: no connection path")
        gaps.setdefault(start, []).append((source, target, path))

    for edges in gaps.values():
        outgoing: dict[str, list[tuple[str, str, ET.Element]]] = {}
        incoming: dict[str, list[tuple[str, str, ET.Element]]] = {}
        for edge in edges:
            outgoing.setdefault(edge[0], []).append(edge)
            incoming.setdefault(edge[1], []).append(edge)
        ports: dict[tuple[str, str], list[float]] = {}
        for node, group in outgoing.items():
            _, top, _, bottom = boxes[node]
            for index, edge in enumerate(
                sorted(
                    group, key=lambda e: ((boxes[e[1]][1] + boxes[e[1]][3]) / 2, e[1])
                )
            ):
                ports.setdefault((edge[0], edge[1]), [0, 0])[0] = top + (
                    bottom - top
                ) * (index + 1) / (len(group) + 1)
        for node, group in incoming.items():
            _, top, _, bottom = boxes[node]
            for index, edge in enumerate(
                sorted(
                    group, key=lambda e: ((boxes[e[0]][1] + boxes[e[0]][3]) / 2, e[0])
                )
            ):
                ports[(edge[0], edge[1])][1] = top + (bottom - top) * (index + 1) / (
                    len(group) + 1
                )

        adjacent = edges
        left = max(boxes[source][2] for source, _, _ in adjacent)
        right = min(boxes[target][0] for _, target, _ in adjacent)
        bent = [
            edge
            for edge in adjacent
            if abs(ports[edge[:2]][0] - ports[edge[:2]][1]) > 0.5
        ]
        lanes = sorted(
            bent, key=lambda e: (ports[e[:2]][0], ports[e[:2]][1]), reverse=True
        )

        draw_column_lanes(lanes, ports, boxes, left, right)
        for source, target, path in adjacent:
            if (source, target, path) not in bent:
                y = ports[(source, target)][0]
                path.set(
                    "d",
                    rounded_orthogonal_path(
                        [
                            (boxes[source][2], y),
                            (boxes[target][0] - 4, y),
                        ]
                    ),
                )

        # Reverse source order avoids most nested-interval crossings. Swap lanes
        # while it reduces crossings with other edges, including untouched long edges.
        best = layout_metrics(ET.tostring(root, encoding="unicode"))["crossings"]
        improved = True
        while improved:
            improved = False
            for i in range(len(lanes)):
                for j in range(i + 1, len(lanes)):
                    lanes[i], lanes[j] = lanes[j], lanes[i]
                    draw_column_lanes(lanes, ports, boxes, left, right)
                    score = layout_metrics(ET.tostring(root, encoding="unicode"))[
                        "crossings"
                    ]
                    if score < best:
                        best = score
                        improved = True
                        break
                    lanes[i], lanes[j] = lanes[j], lanes[i]
                if improved:
                    break
            draw_column_lanes(lanes, ports, boxes, left, right)


def normalize_svg(
    model: dict[str, Any], view: str, source: str
) -> tuple[str, list[str]]:
    """Match d2 groups against the model, then discard d2's untrusted styling/fonts."""
    if "<!DOCTYPE" in source or "<!ENTITY" in source:
        raise DiagramError(f"view {view}: SVG contains a DTD")
    root = ET.fromstring(source)
    tag = lambda name: f"{{{SVG_NS}}}{name}"
    if root.tag != tag("svg") or "viewBox" not in root.attrib:
        raise DiagramError(f"view {view}: d2 did not emit an SVG viewBox")
    allowed = {
        "svg",
        "g",
        "rect",
        "path",
        "text",
        "tspan",
        "polygon",
        "marker",
        "mask",
        "style",
        "title",
        "defs",
        "ellipse",
        "circle",
    }
    attributes = {
        "class",
        "id",
        "xmlns",
        "viewBox",
        "width",
        "height",
        "x",
        "y",
        "x1",
        "y1",
        "x2",
        "y2",
        "rx",
        "ry",
        "cx",
        "cy",
        "r",
        "d",
        "points",
        "fill",
        "stroke",
        "stroke-width",
        "stroke-dasharray",
        "opacity",
        "style",
        "marker-end",
        "marker-start",
        "markerWidth",
        "markerHeight",
        "refX",
        "refY",
        "orient",
        "markerUnits",
        "preserveAspectRatio",
        "shape-rendering",
        "transform",
        "text-anchor",
        "font-size",
        "font-weight",
        "dominant-baseline",
        "dy",
        "dx",
        "mask",
        "data-node",
        "data-edge",
        "data-from",
        "data-to",
        "data-flow",
        "data-kind",
        "data-step-id",
        "role",
        "tabindex",
        "aria-label",
        "aria-pressed",
    }
    semantic_attributes = {
        "data-node",
        "data-edge",
        "data-step-id",
        "data-from",
        "data-to",
        "data-flow",
        "data-kind",
    }
    for parent in list(root.iter()):
        if parent.tag not in {tag(name) for name in allowed}:
            raise DiagramError(f"view {view}: unsafe SVG element {parent.tag}")
        if parent.tag in {tag("style"), tag("mask")}:
            continue
        for element in list(parent):
            if element.tag in {tag("style"), tag("mask")}:
                parent.remove(element)
        for attribute, value in list(parent.attrib.items()):
            if attribute in semantic_attributes:
                raise DiagramError(
                    f"view {view}: pre-existing SVG attribute {attribute}"
                )
            if attribute not in attributes or attribute.lower().startswith("on"):
                raise DiagramError(f"view {view}: unsafe SVG attribute {attribute}")
            if attribute == "style" and (
                "url(" in value.lower()
                or "@" in value
                or not re.fullmatch(r"[\w\s:;.,%-]*", value)
            ):
                raise DiagramError(f"view {view}: unsafe SVG style")
            if attribute in ("fill", "stroke") and not re.fullmatch(
                r"#[0-9a-fA-F]{3,8}|none|transparent|white|black|currentColor|(?:rgba?|hsla?)\([0-9.,%\s]+\)|url\(#[\w-]+\)",
                value,
            ):
                raise DiagramError(
                    f"view {view}: unsafe SVG paint {attribute}={value!r}"
                )
            if attribute in ("marker-end", "marker-start", "mask") and not re.fullmatch(
                r"url\(#[\w-]+\)", value
            ):
                raise DiagramError(f"view {view}: external SVG reference")
            if attribute == "mask":
                parent.attrib.pop("mask", None)
    edges = view_edges(model, view)
    identities = {d2_path(model, item): item for item in drawn_ids(model, edges)}
    expected_edges: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for edge in edges:
        expected_edges.setdefault(
            (d2_path(model, edge["from"]), d2_path(model, edge["to"])), []
        ).append(edge)
    found_nodes: list[str] = []
    found_edges: list[dict[str, Any]] = []
    badge_anchors: list[tuple[float, float]] = []
    seen_pairs: Counter[tuple[str, str]] = Counter()
    for group in root.iter(tag("g")):
        classes = group.get("class", "").split()
        if not classes:
            continue
        try:
            decoded = html.unescape(
                base64.b64decode(classes[0], validate=True).decode()
            )
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded in identities:
            item = identities[decoded]
            if item in found_nodes:
                raise DiagramError(f"view {view}: duplicate SVG node {item}")
            found_nodes.append(item)
            group.set("data-node", item)
            if item in model["frames"] and "frame" in classes:
                classes.append("frame-" + frame_kind(model, item))
            shape = (
                ("workload" if frame_kind(model, item) == "pod" else "service")
                if item in model["frames"]
                else model["nodes"][item]["shape"]
            )
            group.set("class", " ".join(classes))
            fills = {
                "service": ("node-bg", "#ffffff", "border-strong", "#343a40"),
                "external": ("node-bg", "#ffffff", "border-soft", "#adb5bd"),
                "store": ("store-bg", "#fdeada", "border-strong", "#343a40"),
                "object": ("node-bg", "#ffffff", "border-mid", "#868e96"),
                "workload": ("workload-bg", "#e9ecef", "border-workload", "#495057"),
            }
            if "frame" in classes:
                kind = frame_kind(model, item)
                fills_by_frame = {
                    "boundary": ("none", "transparent", "border-mid", "#868e96"),
                    "repeated": ("frame-repeat", "#fcfcfc", "border-mid", "#868e96"),
                    "group": ("none", "transparent", "border-soft", "#adb5bd"),
                    "pod": ("frame-pod", "#f8f9fa", "border-pod", "#ced4da"),
                    "component": ("node-bg", "#ffffff", "border-mid", "#868e96"),
                }
                fill_role, fill_fallback, stroke_role, stroke_fallback = fills_by_frame[
                    kind
                ]
                owner_id = model["frames"][item].get("owner") if item in model["frames"] else None
                if owner_id and owner_id in (model.get("owners") or {}):
                    fill_role = f"owner-{owner_id}"
                    fill_fallback = model["owners"][owner_id]["color"]
            else:
                fill_role, fill_fallback, stroke_role, stroke_fallback = fills[shape]
                owner_id = (
                    model["nodes"][item].get("owner")
                    if item in model["nodes"]
                    else None
                )
                if owner_id and owner_id in (model.get("owners") or {}):
                    fill_role = f"owner-{owner_id}"
                    fill_fallback = model["owners"][owner_id]["color"]
            for form in group.findall(f"{tag('g')}/{tag('rect')}") + group.findall(
                f"{tag('g')}/{tag('path')}"
            ):
                paint(form, "fill", fill_role, fill_fallback)
                paint(form, "stroke", stroke_role, stroke_fallback)
            for text in group.findall(tag("text")):
                if "text-bold" in text.get("class", "").split():
                    text.set("font-weight", "700")
                paint(
                    text,
                    "fill",
                    "edge-label" if "frame" in classes else "node-text",
                    "#5c6570" if "frame" in classes else "#19232d",
                )
                if item in model["nodes"] and "\n" in model["nodes"][item]["label"]:
                    spans = text.findall(tag("tspan"))
                    if len(spans) == 2:
                        paint(spans[1], "fill", "muted", "#667180")
                        spans[1].set("font-weight", "400")
            if "frame" in classes:
                frame_rect = group.find(f"{tag('g')}/{tag('rect')}")
                frame_label = group.find(tag("text"))
                if frame_rect is None or frame_label is None:
                    raise DiagramError(
                        f"view {view}: frame {item} has no rectangle or label"
                    )
                label_x = float(frame_rect.get("x")) + 10
                frame_label.set("x", f"{label_x:g}")
                frame_label.set(
                    "y",
                    f"{max(float(frame_label.get('y')), float(frame_rect.get('y')) + 22):g}",
                )
                frame_label.set(
                    "style",
                    re.sub(
                        r"(?:^|;)text-anchor:[^;]*", "", frame_label.get("style", "")
                    ).strip(";")
                    + ";text-anchor:start",
                )
                for span in frame_label.findall(tag("tspan")):
                    span.set("x", f"{label_x:g}")
            if item in model["nodes"] or model["frames"].get(item, {}).get("doc"):
                group.set("role", "button")
                group.set("tabindex", "0")
                group.set(
                    "aria-label",
                    model["nodes"]
                    .get(item, model["frames"].get(item))["label"]
                    .replace("\n", " "),
                )
                group.set("aria-pressed", "false")
            continue
        match = re.fullmatch(r"(?:(.*)\.)?\((.+) -> (.+)\)\[(\d+)\]", decoded)
        if not match:
            continue
        prefix, start, end, index = match.groups()
        pair = (
            f"{prefix}.{start}" if prefix else start,
            f"{prefix}.{end}" if prefix else end,
        )
        options = expected_edges.get(pair, [])
        ordinal = seen_pairs[pair]
        if not options or ordinal >= len(options) or int(index) != ordinal:
            raise DiagramError(f"view {view}: unmatched SVG edge {decoded}")
        edge = options[ordinal]
        seen_pairs[pair] += 1
        found_edges.append(edge)
        edge_id = (
            f"{view}:step-{edge['number']}"
            if "number" in edge
            else f"{edge['from']}->{edge['to']}"
        )
        for key, value in (
            ("edge", edge_id),
            ("from", edge["from"]),
            ("to", edge["to"]),
            ("flow", edge["flow"]),
            ("kind", edge["kind"]),
        ):
            group.set("data-" + key, value)
        for form in group.iter():
            if (
                form.tag == tag("path")
                and "connection" in form.get("class", "").split()
            ):
                paint(
                    form,
                    "stroke",
                    "flow-" + edge["flow"],
                    model["flows"][edge["flow"]]["color"],
                )
            if (
                form.tag == tag("polygon")
                and "connection" in form.get("class", "").split()
            ):
                paint(
                    form,
                    "fill",
                    "flow-" + edge["flow"],
                    model["flows"][edge["flow"]]["color"],
                )
        labels = group.findall(tag("text"))
        for label in labels:
            paint(label, "fill", "edge-label", "#5c6570")
            paint(label, "stroke", "canvas", "#ffffff")
            label.set(
                "style",
                label.get("style", "") + ";stroke-width:3px;paint-order:stroke fill",
            )
        if "number" in edge:
            step_id = edge_id
            group.set("data-step-id", step_id)
            spans = labels[0].findall(tag("tspan")) if len(labels) == 1 else []
            if len(spans) < FA_STEP_COUNTER_MAX * 2 + 1:
                raise DiagramError(
                    f"view {view}: step {edge['number']} has no reserved label space"
                )
            first = spans[0]
            reserve = "MMMM" * FA_STEP_COUNTER_MAX
            if (first.text or "").strip() != f"{edge['number']} {reserve}" or any(
                (span.text or "").strip() != reserve
                for span in spans[1 : FA_STEP_COUNTER_MAX * 2]
            ):
                raise DiagramError(
                    f"view {view}: step {edge['number']} label does not match layout"
                )
            x, y = (
                first.get("x", labels[0].get("x")),
                first.get("y", labels[0].get("y")),
            )
            if x is None or y is None:
                raise DiagramError(
                    f"view {view}: step {edge['number']} label has no coordinates"
                )
            for span in spans[: FA_STEP_COUNTER_MAX * 2]:
                span.text = "\u00a0"
            # Anchor the bottom of the badge within the reserved multiline label.
            badge_x, badge_y = float(x), float(y) + 45
            badge_anchors.append((badge_x, badge_y))
            badge = ET.SubElement(
                group,
                tag("g"),
                {
                    "class": "fa-step-badge",
                    "data-step-id": step_id,
                    "transform": f"translate({badge_x:g} {badge_y:g})",
                },
            )
            ET.SubElement(
                badge, tag("title")
            ).text = f"Step {edge['number']}: {edge['label']}"
            glyph = ET.SubElement(
                badge,
                tag("g"),
                {
                    "class": "fa-step-glyph",
                    "style": "transform:scale(var(--fa-step-counter-scale,1));transform-origin:0px 0px",
                },
            )
            circle = ET.SubElement(
                glyph, tag("circle"), {"cy": "-14", "r": "14", "stroke-width": "2"}
            )
            paint(circle, "fill", "step-badge-bg", "#ffffff")
            paint(circle, "stroke", "step-badge-ink", "#212529")
            digit = ET.SubElement(
                glyph,
                tag("text"),
                {
                    "text-anchor": "middle",
                    "dominant-baseline": "central",
                    "font-size": "18",
                    "font-weight": "700",
                    "y": "-14",
                    "stroke": "none",
                },
            )
            digit.text = str(edge["number"])
            paint(digit, "fill", "step-badge-ink", "#212529")
    expected_ids = drawn_ids(model, edges)
    if set(found_nodes) != expected_ids or len(found_edges) != len(edges):
        raise DiagramError(
            f"view {view}: SVG group mismatch; missing nodes {sorted(expected_ids - set(found_nodes))}, edges {len(found_edges)}/{len(edges)}"
        )
    expected_edge_ids = Counter(
        f"{view}:step-{edge['number']}"
        if "number" in edge
        else f"{edge['from']}->{edge['to']}"
        for edge in edges
    )
    node_ids = Counter(
        element.get("data-node")
        for element in root.iter()
        if element.get("data-node") is not None
    )
    edge_ids = Counter(
        element.get("data-edge")
        for element in root.iter()
        if element.get("data-edge") is not None
    )
    step_ids = Counter(
        element.get("data-step-id")
        for element in root.iter()
        if element.get("data-step-id") is not None
    )
    expected_step_ids = (
        Counter({edge_id: 2 for edge_id in expected_edge_ids if ":step-" in edge_id})
        if next(v for v in model["views"] if v["id"] == view)["category"] == "flow"
        else Counter()
    )
    if (
        node_ids != Counter(expected_ids)
        or edge_ids != expected_edge_ids
        or step_ids != expected_step_ids
    ):
        raise DiagramError(
            f"view {view}: non-unique or unmatched SVG semantic attributes"
        )
    for element in root.iter():
        if element.tag == tag("rect") and "fill-N7" in element.get("class", "").split():
            paint(element, "fill", "canvas", "#ffffff")
        if (
            element.tag == tag("text")
            and "fill-N1" in element.get("class", "").split()
            and not element.get("fill", "").startswith("var(")
        ):
            paint(element, "fill", "node-text", "#19232d")
    if badge_anchors:
        inner = root.find(tag("svg"))
        if inner is None:
            raise DiagramError(f"view {view}: no inner SVG to pad for badges")
        x, y, w, h = map(float, inner.get("viewBox", "").split())
        badge_half_width = 15 * FA_STEP_COUNTER_MAX
        badge_height = 30 * FA_STEP_COUNTER_MAX
        left = max(40, x - min(bx - badge_half_width for bx, _ in badge_anchors) + 12)
        top = max(40, y - min(by - badge_height for _, by in badge_anchors) + 12)
        right = max(
            40, max(bx + badge_half_width for bx, _ in badge_anchors) - (x + w) + 12
        )
        bottom = max(40, max(by + 60 for _, by in badge_anchors) - (y + h) + 12)
        inner.set(
            "viewBox",
            f"{x - left:g} {y - top:g} {w + left + right:g} {h + top + bottom:g}",
        )
        inner.set("width", f"{w + left + right:g}")
        inner.set("height", f"{h + top + bottom:g}")
        root.set("viewBox", f"0 0 {w + left + right:g} {h + top + bottom:g}")
    root.attrib.pop("width", None)
    root.attrib.pop("height", None)
    if (
        next(v for v in model["views"] if v["id"] == view)
        .get("layout", {})
        .get("route")
        == "orthogonal"
    ):
        route_adjacent_columns(root)
    selection = ET.SubElement(root, tag("style"))
    selection.text = (
        ".is-selected > .shape > rect, .is-selected > .shape > path {"
        "stroke: var(--fa-selection-stroke, #1864ab); stroke-width: 3px}"
    )
    return ET.tostring(root, encoding="unicode"), found_nodes


# --------------------------------------------------------------------- Markdown


def inline_text(tokens: list[Token]) -> str:
    parts: list[str] = []
    for token in tokens:
        if token.type in {"text", "code_inline", "image"}:
            parts.append(token.content)
        elif token.type in {"softbreak", "hardbreak"}:
            parts.append(" ")
    return " ".join("".join(parts).split())


def repo_hrefs(tokens: list[Token]) -> list[str]:
    return [
        href
        for token in tokens
        if token.type == "link_open"
        for href in [token.attrGet("href")]
        if isinstance(href, str)
        and "github.com/" in href
        and ("/tree/" in href or "/blob/" in href)
    ]


def parse_comment(content: str, line: int) -> tuple[str, dict[str, str]] | None:
    """('catalog' | 'view', fields) for an annotation comment, or None."""
    text = content.strip()
    if not (text.startswith("<!--") and text.endswith("-->")):
        return None
    body = text.removeprefix("<!--").removesuffix("-->").strip()
    marker, _, payload = body.partition(":")
    marker = marker.strip()
    location = f"{MARKDOWN_PATH.name}:{line}"
    if marker == "view":
        return "view", {"id": payload.strip()}
    if marker != "catalog":
        return None
    fields: dict[str, str] = {}
    for field in shlex.split(payload):
        key, separator, value = field.partition("=")
        if not separator and key == "no-service":
            fields[key] = ""
        elif separator and key in ("dd_service", "dashboard") and value:
            fields[key] = value
        else:
            raise DiagramError(f"{location}: unknown catalog field {field!r}")
    return "catalog", fields


def section_body(lines: list[str], start: int, end: int | None) -> str:
    body = re.sub(r"(?s)<!--.*?-->", "", "\n".join(lines[start:end]))
    return "\n".join(line.rstrip() for line in body.strip().splitlines()).strip()


def read_markdown() -> tuple[dict[str, str], list[dict[str, Any]]]:
    """(view id -> intro html, box sections)."""
    source = MARKDOWN_PATH.read_text()
    lines, tokens = source.splitlines(), ANNOTATIONS.parse(source)
    heads = [
        (
            token.tag,
            inline_text(tokens[index + 1].children or []),
            token.map[0],
            token.map[1],
            index,
        )
        for index, token in enumerate(tokens)
        if token.type == "heading_open"
    ]

    views: dict[str, str] = {}
    sections: list[dict[str, Any]] = []
    for position, (tag, name, start, body_start, index) in enumerate(heads):
        end = heads[position + 1][2] if position + 1 < len(heads) else None
        # the h2 intro runs to its first h3
        own_end = end
        for later in heads[position + 1 :]:
            if later[0] in {"h1", "h2", "h3"}:
                own_end = later[2]
                break
        annotations = [
            parse_comment(t.content, (t.map[0] + 1) if t.map else 0)
            for t in tokens[index:]
            if t.type == "html_block"
            and t.map
            and body_start <= t.map[0] < (own_end if own_end is not None else 1 << 30)
        ]
        annotations = [a for a in annotations if a]
        if tag == "h2":
            for kind, fields in annotations:
                if kind == "view":
                    if fields["id"] in views:
                        raise DiagramError(f"duplicate Markdown view {fields['id']}")
                    views[fields["id"]] = render_markdown(
                        section_body(lines, body_start, own_end)
                    )
        if tag == "h3":
            catalog = next((f for k, f in annotations if k == "catalog"), None)
            if catalog is None:
                continue
            body_tokens = [
                t
                for t in tokens[index:]
                if t.map and body_start <= t.map[0] < (own_end or 1 << 30)
            ]
            repos = [
                href
                for t in body_tokens
                if t.type == "inline"
                for href in repo_hrefs(t.children or [])
            ]
            sections.append(
                {
                    "name": name,
                    "slug": slugify(name),
                    "description": section_body(lines, body_start, own_end),
                    "dd_service": None
                    if "no-service" in catalog
                    else catalog.get("dd_service", slugify(name)),
                    "repos": repos,
                    "dashboard": catalog.get("dashboard"),
                }
            )
    return views, sections


# ------------------------------------------------------------------ source links

SOURCE_PARAGRAPH = re.compile(r"<p>Source:(.*?)</p>", re.DOTALL)
CODE_SPAN = re.compile(r"<code>([^<]+)</code>")
SOURCE_DETAIL = re.compile(
    r"\(\s*(?P<code><code>[^<]+</code>(?:\s*,\s*<code>[^<]+</code>)*)\s*\)"
    r"|\((?P<text>[^<>()`]+)\)"
)
SOURCE_SEPARATOR = re.compile(r"(?:[,;]\s*(?:and\b\s*)?|and\b\s*)")
SOURCE_REPOSITORY_MARKER = re.compile(r"in\s+([a-z][a-z0-9-]*),\s*")


def repo_base(site: dict[str, Any]) -> str | None:
    """https://github.com/<org>/<repo>/<tree|blob>/<branch> prefix of site.source_url."""
    match = re.match(
        r"(https://github\.com/[^/]+/[^/]+)/(?:tree|blob)/([^/]+)/",
        site.get("source_url", ""),
    )
    return f"{match.group(1)}/%s/{match.group(2)}" if match else None


def source_href(path: str, base: str | None, repository: str | None) -> str | None:
    """A GitHub link for a cited path, or None when it is not a path we can resolve."""
    path = path.strip()
    if not re.fullmatch(r"[\w.@/-]+", path) or "/" not in path:
        return None
    if repository:
        kind = (
            "tree"
            if path.endswith("/") or "." not in path.rsplit("/", 1)[-1]
            else "blob"
        )
        return SOURCE_REPOSITORIES[repository] % kind + "/" + path.rstrip("/")
    target = REPO_ROOT / path
    if base is None or not target.exists():
        return None
    return base % ("tree" if target.is_dir() else "blob") + "/" + path.rstrip("/")


def extract_sources(
    rendered: str, base: str | None, where: str
) -> tuple[str, list[dict[str, str | None]], list[str]]:
    """Remove Source paragraphs, returning citations and the original chip-link order."""
    sources: list[dict[str, str | None]] = []
    links: list[str] = []

    def paragraph(match: re.Match[str]) -> str:
        authored = html.unescape(re.sub(r"</?code>", "`", match.group(1))).strip()
        error = DiagramError(f"{where}: invalid Source paragraph: {authored!r}")
        body = match.group(1).strip().removesuffix(".").rstrip()
        position = 0
        repository = None
        while True:
            if marker := SOURCE_REPOSITORY_MARKER.match(body, position):
                repository = marker.group(1)
                if repository not in SOURCE_REPOSITORIES:
                    raise DiagramError(
                        f"{where}: unknown source repository {repository!r}; configure site.source_repositories"
                    )
                position = marker.end()
            entry_start = position
            code = CODE_SPAN.match(body, position)
            if not code:
                raise error
            text = html.unescape(code.group(1))
            href = source_href(text, base, repository)
            position = code.end()
            position += len(body[position:]) - len(body[position:].lstrip())
            detail = None
            if qualifier := SOURCE_DETAIL.match(body, position):
                detail = (
                    ", ".join(
                        html.unescape(span.group(1))
                        for span in CODE_SPAN.finditer(qualifier.group("code"))
                    )
                    if qualifier.group("code")
                    else " ".join(html.unescape(qualifier.group("text")).split())
                )
                if not detail:
                    raise error
                position = qualifier.end()
                position += len(body[position:]) - len(body[position:].lstrip())
            sources.append({"text": text, "href": href, "detail": detail})
            # Preserve chip selection even when a parenthetical code span is a path.
            for span in CODE_SPAN.finditer(body, entry_start, position):
                link = source_href(html.unescape(span.group(1)), base, repository)
                if link:
                    links.append(link)
            if position == len(body):
                break
            separator = SOURCE_SEPARATOR.match(body, position)
            if not separator:
                raise error
            position = separator.end()

        return ""

    return SOURCE_PARAGRAPH.sub(paragraph, rendered).strip(), sources, links


# ---------------------------------------------------- Datadog service definitions


def document_service_name(document: dict[str, Any]) -> str | None:
    if document.get("apiVersion") == "v3":
        return document.get("metadata", {}).get("name")
    return document.get("dd-service")


def document_repos(document: dict[str, Any]) -> list[str]:
    if document.get("apiVersion") == "v3":
        document = document.get("metadata") or {}
    entries = [
        *(document.get("repos") or []),
        *(
            link
            for link in document.get("links") or []
            if isinstance(link, dict) and link.get("type") == "repo"
        ),
    ]
    return [
        entry["url"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("url"), str)
    ]


def document_wiki(document: dict[str, Any]) -> str | None:
    if document.get("apiVersion") == "v3":
        document = document.get("metadata") or {}
    entries = [
        *(document.get("docs") or []),
        *(
            link
            for link in document.get("links") or []
            if isinstance(link, dict) and link.get("type") == "doc"
        ),
    ]
    pages = [
        (entry.get("name") or "", entry["url"])
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("url"), str)
        and not WIKI_SKIP.search(entry.get("name") or "")
        and not WIKI_SPACE.search(entry["url"])
    ]
    if not pages:
        return None

    def rank(entry: tuple[int, tuple[str, str]]) -> tuple[int, int]:
        position, (name, _) = entry
        title = name.strip().lower()
        return (
            WIKI_NAMES.index(title) if title in WIKI_NAMES else len(WIKI_NAMES)
        ), position

    return min(enumerate(pages), key=rank)[1][1]


def document_dashboard(document: dict[str, Any]) -> str | None:
    """The first production dashboard the service definition links."""
    if document.get("apiVersion") == "v3":
        document = document.get("metadata") or {}
    return next(
        (
            link["url"]
            for link in document.get("links") or []
            if isinstance(link, dict)
            and link.get("type") == "dashboard"
            and str(link.get("url", "")).startswith("https://app.datadoghq.com/")
        ),
        None,
    )


def resolve_definitions(sections: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    wanted = {s["dd_service"] for s in sections if s["dd_service"]}
    found: dict[str, list[tuple[Path, dict[str, Any]]]] = {
        service: [] for service in wanted
    }
    for path in sorted(REPO_ROOT.rglob("service.datadog.yaml")):
        if any(
            part in str(path)
            for part in ("/.bazel", "/node_modules/", "/.claude/worktrees/", "/bazel-")
        ):
            continue
        try:
            documents = list(yaml.safe_load_all(path.read_text()))
        except (OSError, yaml.YAMLError) as error:
            raise DiagramError(
                f"cannot read service definition {path}: {error}"
            ) from error
        for document in documents:
            service = document_service_name(document or {})
            if service in wanted:
                found[service].append(
                    (
                        path,
                        {
                            "repos": document_repos(document),
                            "wiki": document_wiki(document),
                            "dashboard": document_dashboard(document),
                        },
                    )
                )
    resolved: dict[str, dict[str, Any]] = {}
    for service, matches in found.items():
        if not matches:
            raise DiagramError(
                f"no service definition found for {service!r} under {REPO_ROOT}"
            )
        if len(matches) > 1:
            raise DiagramError(
                f"multiple service definitions for {service!r}: "
                + ", ".join(str(p) for p, _ in matches)
            )
        resolved[service] = matches[0][1]
    return resolved


def service_links(
    urls: list[str],
    wiki: str | None,
    service: str | None,
    dashboard: str | None,
    sources: list[str],
) -> dict[str, str]:
    charts = [url for url in urls if re.search(r"/(k8s|kubernetes|helm)(/|$)", url)]
    code = [url for url in urls if url not in charts]
    # a chart in this repository that the section cites beats a definition's link,
    # which can point at a chart that has since moved
    repo_charts = []
    for url in sources:
        match = re.match(
            r"(https://github\.com/[^/]+/[^/]+)/(?:tree|blob)/([^/]+)/k8s/([^/]+)", url
        )
        if match and (REPO_ROOT / "k8s" / match.group(3) / "Chart.yaml").exists():
            repo_charts.append(
                f"{match.group(1)}/tree/{match.group(2)}/k8s/{match.group(3)}"
            )
    if repo_charts and (charts or service):
        charts = [repo_charts[0]]
    links: dict[str, str] = {}
    if code:

        def rank(entry: tuple[int, str]) -> tuple[bool, bool, int]:
            position, url = entry
            is_file = "/blob/" in url
            return "/apps/" not in url, is_file, position if is_file else len(url)

        links["code"] = min(enumerate(code), key=rank)[1]
    elif code_sources := [url for url in sources if not url.endswith(".md")]:
        links["code"] = code_sources[0]
    if wiki:
        links["wiki"] = wiki
    if charts:
        links["k8s_chart"] = charts[0]
    if service:
        tag = quote(f"service:{service}", safe="")
        links["datadog_service"] = f"https://app.datadoghq.com/apm/entity/{tag}"
        # only something deployed to Kubernetes writes logs under its service tag
        if charts:
            links["logs"] = f"https://app.datadoghq.com/logs?query={tag}"
    if dashboard:
        links["dashboard"] = dashboard
    return links


def build_docs(
    sections: list[dict[str, Any]],
    definitions: dict[str, dict[str, Any]],
    base: str | None,
) -> dict[str, Any]:
    docs: dict[str, Any] = {}
    for section in sections:
        if not section["description"]:
            raise DiagramError(f"Markdown section {section['name']!r} has no prose")
        if section["slug"] in docs:
            raise DiagramError(f"duplicate Markdown section {section['name']!r}")
        definition = definitions.get(section["dd_service"]) or {}
        urls = list(dict.fromkeys([*section["repos"], *definition.get("repos", [])]))
        description, sources, source_links = extract_sources(
            render_markdown(section["description"]),
            base,
            f"Markdown section {section['name']!r}",
        )
        entry: dict[str, Any] = {
            "name": section["name"],
            "descriptionHtml": description,
            "sources": sources,
            "links": {},
        }
        links = service_links(
            urls,
            definition.get("wiki"),
            section["dd_service"],
            section["dashboard"] or definition.get("dashboard"),
            source_links,
        )
        entry["links"] = safe_links(links, f"doc {section['slug']}")
        docs[section["slug"]] = entry
    return docs


# ------------------------------------------------------------------------- main


def export_web_ui(root: Path, data_path: Path, app: str) -> None:
    destination = root / "static-apps" / app / "src"
    if not destination.parent.is_dir():
        raise DiagramError(f"--web-ui: no static-apps/{app} under {root}")
    if not destination.resolve().is_relative_to(root.resolve()):
        raise DiagramError("--web-ui: export destination escapes the checkout")
    destination.mkdir(parents=True, exist_ok=True)
    for name in EXPORT_FILES:
        source, target = SCRIPT_DIR / "src" / name, destination / name
        if source.is_file():
            shutil.copyfile(source, target)
        elif target.is_file():
            target.unlink()
    shutil.copyfile(data_path, destination / "architecture-data.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--d2", type=Path, help="also write the generated d2 source here"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only validate model.yaml and the Markdown; needs no d2",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=SCRIPT_DIR / "dist/src",
        help="JSON output directory",
    )
    parser.add_argument(
        "--web-ui", type=Path, help="export owned source and JSON to a web-ui checkout"
    )
    args = parser.parse_args()

    model = load_model()
    view_intros, sections = read_markdown()
    base = repo_base(model["site"])
    docs = build_docs(sections, resolve_definitions(sections), base)

    # every box and clickable frame must have a panel section, and every view an intro
    doc_of = {nid: node.get("doc", nid) for nid, node in model["nodes"].items()}
    doc_of.update({fid: f["doc"] for fid, f in model["frames"].items() if f.get("doc")})
    missing = sorted({slug for slug in doc_of.values() if slug not in docs})
    missing += [f"view {v['id']}" for v in model["views"] if v["id"] not in view_intros]
    if missing:
        raise DiagramError(
            f"{MARKDOWN_PATH.name} has no section for: " + ", ".join(missing)
        )
    unused = sorted(set(docs) - set(doc_of.values()))
    if unused:
        print(
            f"note: sections not linked from any box: {', '.join(unused)}",
            file=sys.stderr,
        )

    unknown = set(view_intros) - {v["id"] for v in model["views"]}
    if unknown:
        raise DiagramError(f"{MARKDOWN_PATH.name}: unknown views {sorted(unknown)}")
    intros = {
        view["id"]: extract_sources(
            view_intros[view["id"]],
            base,
            f"Markdown view {view['id']!r} ({view['title']})",
        )
        for view in model["views"]
    }
    if args.check:
        print(f"model.yaml and {MARKDOWN_PATH.name} are consistent")
        return 0

    boards = render_boards(model, args.d2)
    related = {v["id"]: [] for v in model["views"]}
    for view in model["views"]:
        if view["category"] == "flow":
            related[view["scenario"]["architecture_view"]].append(view["id"])
    categories = [
        {
            "id": category,
            "title": title,
            "groups": list(
                dict.fromkeys(
                    v["group"] for v in model["views"] if v["category"] == category
                )
            ),
        }
        for category, title in (
            ("architecture", "Architecture Diagrams"),
            ("flow", "Flows"),
        )
    ]
    diagrams: dict[str, str] = {}
    views = []
    for view in model["views"]:
        vid = view["id"]
        edges = view_edges(model, vid)
        diagrams[vid], node_ids = normalize_svg(model, vid, boards[vid])
        intro, sources, source_links = intros[vid]
        links = safe_links(
            {"code": source_links[0]} if source_links else {}, f"view {vid}"
        )
        steps = []
        if view["category"] == "flow":
            for number, (step, edge) in enumerate(zip(view["steps"], edges), 1):
                step_id = f"{vid}:step-{number}"
                refs = []
                for ref in step["sources"]:
                    url = f"{base % 'blob'}/{quote(ref['path'])}" if base else ""
                    if "lines" in ref:
                        url += f"#L{ref['lines'][0]}-L{ref['lines'][1]}"
                    refs.append({**ref, "url": safe_url(url, f"view {vid} source")})
                steps.append(
                    {
                        "id": step_id,
                        "number": number,
                        "edgeId": step_id,
                        "from": step["from"],
                        "to": step["to"],
                        "label": step["label"],
                        "flow": edge["flow"],
                        "kind": edge["kind"],
                        "verification": step["verification"],
                        "sources": refs,
                        **({"note": step["note"]} if step.get("note") else {}),
                    }
                )
        scenario = view.get("scenario")
        views.append(
            {
                "id": vid,
                "title": view["title"],
                "category": view["category"],
                "group": view["group"],
                "introHtml": intro,
                "sources": sources,
                "links": links,
                "nodeIds": node_ids,
                "flowIds": [
                    flow
                    for flow in model["flows"]
                    if any(e["flow"] == flow for e in edges)
                ],
                "relatedFlows": related[vid],
                "edges": [
                    {
                        "id": f"{vid}:step-{e['number']}"
                        if "number" in e
                        else f"{e['from']}->{e['to']}",
                        "from": e["from"],
                        "to": e["to"],
                        "flow": e["flow"],
                        "kind": e["kind"],
                        "label": e["label"],
                    }
                    for e in edges
                ],
                "scenario": {
                    "actor": scenario["actor"],
                    "trigger": scenario["trigger"],
                    "preconditions": scenario["preconditions"],
                    "endState": scenario["end_state"],
                    "limitations": scenario["limitations"],
                    "architectureView": scenario["architecture_view"],
                }
                if scenario
                else None,
                "steps": steps,
            }
        )
    used_kinds = {frame_kind(model, fid) for fid in model["frames"]}
    rum = model["site"].get("rum")
    data = {
        "schemaVersion": 1,
        "site": {
            "title": model["site"]["title"],
            "sourceUrl": model["site"].get("source_url", ""),
            "theme": model["site"]["theme"],
            "rum": {
                "applicationId": rum["application_id"],
                "clientToken": rum["client_token"],
                "service": rum["service"],
                "site": rum.get("site", "datadoghq.com"),
                "env": rum.get("env", "staging"),
            }
            if rum
            else None,
        },
        "categories": categories,
        "nodes": {
            **{
                fid: {"label": frame["label"], "shape": None, "isFrame": True}
                for fid, frame in model["frames"].items()
            },
            **{
                nid: {
                    "label": node["label"],
                    "shape": node["shape"],
                    "isFrame": False,
                    "owner": node.get("owner"),
                }
                for nid, node in model["nodes"].items()
            },
        },
        "docOf": doc_of,
        "docs": docs,
        "views": views,
        "legend": {
            "flows": model["flows"],
            "kinds": model["kinds"],
            "shapes": model["shapes"],
            "owners": model.get("owners")
            or {},
            "frames": {
                kind: entry
                for kind, entry in (model.get("frame_kinds") or {}).items()
                if kind in used_kinds
            },
        },
        "diagrams": diagrams,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    data_path = args.output / "architecture-data.json"
    data_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    if args.web_ui:
        export_web_ui(args.web_ui, data_path, model["site"]["app"])
    print(f"wrote {len(views)} views to {data_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiagramError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
