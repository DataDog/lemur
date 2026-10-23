#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["websocket-client>=1.8,<2"]
# ///

"""Check flow badge geometry in a served native build using headless Chrome."""

import argparse
import base64
import json
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket

MEASURE = """(() => {
    const board = document.querySelector('.fa-board');
    const svg = board.querySelector('svg');
    const bounds = svg.getBoundingClientRect();
    const scale = bounds.width / svg.viewBox.baseVal.width;
    const counter = Number(getComputedStyle(board).getPropertyValue('--fa-step-counter-scale'));
    const intersects = (circle, rect) => {
        const x = circle.x + circle.width / 2, y = circle.y + circle.height / 2;
        return Math.hypot(x - Math.max(rect.left, Math.min(x, rect.right)),
            y - Math.max(rect.top, Math.min(y, rect.bottom))) < circle.width / 2 - 0.1;
    };
    const textRects = (node) => [...node.querySelectorAll(':scope > text')].flatMap(text => {
        const lines = [...text.querySelectorAll('tspan')].filter(line => line.textContent.trim());
        return (lines.length ? lines : [text]).map(line => line.getBoundingClientRect());
    });
    const nodes = [...board.querySelectorAll('[data-node]')];
    return {
        scale, counter,
        badges: [...board.querySelectorAll('.fa-step-badge circle')].map(circle => {
            const rect = circle.getBoundingClientRect();
            const edge = circle.closest('[data-edge]');
            return {
                step: edge.dataset.stepId,
                bounds: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
                ownLabel: textRects(edge).some(label => intersects(rect, label)),
                nodeLabels: nodes.filter(node => textRects(node).some(label => intersects(rect, label)))
                    .map(node => node.dataset.node),
                // Enclosing frames are expected to contain badges; their labels are checked above.
                nodeBoxes: nodes.filter(node => !node.classList.contains('frame') &&
                    [...node.querySelectorAll(':scope > .shape')].some(shape => intersects(rect, shape.getBoundingClientRect())))
                    .map(node => node.dataset.node),
                outsideSvg: rect.left < bounds.left - 0.1 || rect.right > bounds.right + 0.1 ||
                    rect.top < bounds.top - 0.1 || rect.bottom > bounds.bottom + 0.1,
            };
        }),
    };
})()"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data", type=Path, required=True, help="JSON used in the build"
    )
    parser.add_argument("--url", required=True, help="Served native app URL")
    parser.add_argument(
        "--output", type=Path, required=True, help="Report/screenshots directory"
    )
    parser.add_argument(
        "--chrome",
        default="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )
    args = parser.parse_args()
    data = json.loads(args.data.read_text())
    flows = [view for view in data["views"] if view["category"] == "flow"]
    if not flows:
        parser.error("--data has no flow views")
    args.output.mkdir(parents=True, exist_ok=True)
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    cases, failures, exceptions = [], [], []
    with (
        tempfile.TemporaryDirectory(prefix="architecture-geometry-") as profile,
        (args.output / "chrome.log").open("w") as log,
    ):
        process = subprocess.Popen(
            [
                args.chrome,
                "--headless=new",
                "--disable-gpu",
                f"--remote-debugging-port={port}",
                "--remote-allow-origins=*",
                f"--user-data-dir={profile}",
                "about:blank",
            ],
            stdout=log,
            stderr=log,
        )
        try:
            for attempt in range(100):
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/json", timeout=1
                    ) as response:
                        pages = json.load(response)
                    break
                except OSError:
                    if attempt == 99:
                        raise
                    time.sleep(0.1)
            page = next(page for page in pages if page["type"] == "page")
            connection = websocket.create_connection(
                page["webSocketDebuggerUrl"], timeout=30
            )
            sequence = 0

            def call(method, **params):
                nonlocal sequence
                sequence += 1
                connection.send(
                    json.dumps({"id": sequence, "method": method, "params": params})
                )
                while True:
                    message = json.loads(connection.recv())
                    if message.get("method") == "Runtime.exceptionThrown":
                        exceptions.append(message)
                    if message.get("id") == sequence:
                        if "error" in message:
                            raise RuntimeError(message["error"])
                        return message.get("result", {})

            def evaluate(expression):
                result = call(
                    "Runtime.evaluate",
                    expression=expression,
                    returnByValue=True,
                    awaitPromise=True,
                )
                if "exceptionDetails" in result:
                    raise RuntimeError(result["exceptionDetails"])
                return result.get("result", {}).get("value")

            def wait(expression):
                for _ in range(100):
                    if evaluate(expression):
                        return
                    time.sleep(0.1)
                raise AssertionError(f"Timed out: {expression}")

            def click(label):
                evaluate(
                    f"[...document.querySelectorAll('button')].find(b => b.textContent.trim() === {json.dumps(label)}).click()"
                )
                time.sleep(0.15)

            call("Runtime.enable")
            call("Page.enable")
            call(
                "Page.navigate",
                url=args.url.split("#")[0] + "#" + data["views"][0]["id"],
            )
            wait("!!document.querySelector('.fa-board svg')")
            evaluate("localStorage.setItem('architecture-panel-width', '372')")
            call("Page.reload")
            wait("!!document.querySelector('.fa-board svg')")
            for width in (1440, 390):
                call(
                    "Emulation.setDeviceMetricsOverride",
                    width=width,
                    height=1050,
                    deviceScaleFactor=1,
                    mobile=False,
                )
                for theme in ("Light", "Dark"):
                    click(theme)
                    for view in flows:
                        evaluate("location.hash = " + json.dumps(view["id"]))
                        wait(
                            "document.querySelector('h2').textContent === "
                            + json.dumps(view["title"])
                        )
                        evaluate("document.fonts.ready.then(() => true)")
                        for mode, label in (
                            ("fit", "Fit all"),
                            ("readable", "Readable"),
                        ):
                            click(label)
                            evaluate(
                                "scrollTo(0,0);document.querySelector('.fa-aside').scrollTo(0,0)"
                            )
                            result = evaluate(MEASURE)
                            result.update(
                                view=view["id"],
                                width=width,
                                theme=theme.lower(),
                                mode=mode,
                            )
                            problems = []
                            if {badge["step"] for badge in result["badges"]} != {
                                step["id"] for step in view["steps"]
                            }:
                                problems.append("Build/data step IDs differ")
                            expected = min(max(1 / result["scale"], 1), 2)
                            if abs(result["counter"] - expected) > 0.01:
                                problems.append(
                                    f"Counter scale {result['counter']} differs from clamped {expected}"
                                )
                            for badge in result["badges"]:
                                for field in (
                                    "ownLabel",
                                    "nodeLabels",
                                    "nodeBoxes",
                                    "outsideSvg",
                                ):
                                    if badge[field]:
                                        problems.append(
                                            f"{badge['step']}: {field}={badge[field]}"
                                        )
                            result["failures"] = problems
                            cases.append(result)
                            name = f"{view['id']}-{theme.lower()}-{width}-{mode}"
                            image = call("Page.captureScreenshot", format="png")
                            (args.output / f"{name}.png").write_bytes(
                                base64.b64decode(image["data"])
                            )
                            if problems:
                                failures.append({"case": name, "problems": problems})
            connection.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    report = {"cases": cases, "failures": failures, "runtimeExceptions": exceptions}
    (args.output / "geometry.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"{len(cases)} cases, {sum(len(case['badges']) for case in cases)} badge checks, "
        f"{len(failures)} failing cases, {len(exceptions)} runtime exceptions"
    )
    print(f"Report and screenshots: {args.output}")
    for failure in failures:
        print(f"FAIL {failure['case']}: {'; '.join(failure['problems'])}")
    return 1 if failures or exceptions else 0


if __name__ == "__main__":
    raise SystemExit(main())
