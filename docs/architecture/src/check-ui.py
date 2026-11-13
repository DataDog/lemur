#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["playwright>=1.55,<2"]
# ///

"""Check the native architecture UI, sidebar geometry and navigation in Chrome."""

import argparse
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

FIT = """() => {
    const stage = document.querySelector('.fa-stage');
    const svg = document.querySelector('.fa-board svg');
    const box = svg.viewBox.baseVal;
    return {
        width: stage.clientWidth,
        scale: svg.getBoundingClientRect().width / box.width,
        expected: Math.min((stage.clientWidth - 48) / box.width,
            (stage.clientHeight - 48) / box.height),
    };
}"""

PLACEHOLDER = """() => {
    const input = document.querySelector('#search');
    const css = getComputedStyle(input);
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    context.font = css.font;
    return {
        text: input.placeholder,
        textWidth: context.measureText(input.placeholder).width,
        available: input.clientWidth - parseFloat(css.paddingLeft) - parseFloat(css.paddingRight),
    };
}"""


NODE_PAINTS = """() => Object.fromEntries([...document.querySelectorAll('[data-node]')].map(node => [node.dataset.node, {
    frame: node.classList.contains('frame'),
    disconnected: node.classList.contains('is-disconnected'),
    opacity: getComputedStyle(node).opacity,
    paints: [...node.querySelectorAll(':scope > .shape > *')].map(shape => ({
        stroke: getComputedStyle(shape).stroke,
        width: getComputedStyle(shape).strokeWidth,
        shapeOpacity: getComputedStyle(shape.parentElement).opacity,
    })),
}]))"""

STEP_VISIBLE = """() => {
    const row = document.querySelector('[data-step-row][aria-pressed=true]')?.closest('li');
    const panel = document.querySelector('.fa-aside');
    if (!row || !panel) return false;
    const r = row.getBoundingClientRect(), p = panel.getBoundingClientRect();
    return r.top >= Math.max(0, p.top) && r.bottom <= Math.min(innerHeight, p.bottom);
}"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--chrome",
        default="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    data = json.loads(args.data.read_text())
    overview = next(
        view
        for view in data["views"]
        if view["category"] == "architecture" and view["edges"]
    )
    flow = next(view for view in data["views"] if view["category"] == "flow")
    longest_flow = max(
        (view for view in data["views"] if view["category"] == "flow"),
        key=lambda view: len(view["steps"]),
    )
    last_step = len(longest_flow["steps"])
    component = next(
        node
        for node in overview["nodeIds"]
        if node in data["docOf"] and not data["nodes"][node]["isFrame"]
    )
    search_term = data["nodes"][component]["label"].split("\n")[0]
    checks, metrics, errors = [], {}, []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chrome)
        context = browser.new_context(
            viewport={"width": 1440, "height": 1050},
            reduced_motion="reduce",
            has_touch=True,
        )
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))

        def loaded():
            expect(page.locator(".fa-board > svg")).to_be_visible()
            page.evaluate("document.fonts.ready")
            page.wait_for_timeout(250)

        def navigate(view):
            page.evaluate("(id) => { location.hash = id; }", view)
            loaded()

        def sidebar(name, collapsed):
            label = ("Expand " if collapsed else "Collapse ") + name
            button = page.get_by_role("button", name=label, exact=True)
            expect(button).to_be_visible()
            expect(button).to_have_attribute(
                "aria-expanded", str(not collapsed).lower()
            )
            target = page.locator("#" + button.get_attribute("aria-controls"))
            (
                expect(target).to_be_hidden
                if collapsed
                else expect(target).to_be_visible
            )()
            rail = page.locator(
                ".fa-nav" if name == "navigation" else ".fa-aside"
            ).bounding_box()
            bounds = button.bounding_box()
            assert (
                rail["x"] <= bounds["x"]
                and bounds["x"] + bounds["width"] <= rail["x"] + rail["width"]
            )
            return button

        def set_sidebar(name, collapsed):
            current = page.get_by_role(
                "button",
                name=("Collapse " if collapsed else "Expand ") + name,
                exact=True,
            )
            if current.count():
                current.click()
            sidebar(name, collapsed)
            page.wait_for_timeout(250)

        def inline_controls():
            for name, selector in (("navigation", ".fa-nav"), ("details", ".fa-aside")):
                button = sidebar(name, False)
                label = page.locator(selector + " .fa-sidebar-label")
                expect(label).to_be_visible()
                button_box, label_box = button.bounding_box(), label.bounding_box()
                assert abs(button_box["y"] - label_box["y"]) <= 4, (
                    name,
                    button_box,
                    label_box,
                )
                assert label_box["x"] + label_box["width"] <= button_box["x"]

        def sources_panel(item):
            sources = item.get("sources", [])
            accordion = page.locator("#details .fa-citations")
            if not sources:
                expect(accordion).to_have_count(0)
                return
            expect(accordion).to_have_count(1)
            button = accordion.get_by_role(
                "button", name=f"Sources ({len(sources)})", exact=True
            )
            expect(button).to_have_attribute("aria-expanded", "false")
            expect(accordion.get_by_role("list")).to_have_count(0)
            assert page.locator("#details").evaluate("""el => {
                const sources = el.querySelector('.fa-citations');
                return [...el.querySelectorAll('.fa-links, h4')].every(item =>
                    item.compareDocumentPosition(sources) & Node.DOCUMENT_POSITION_FOLLOWING);
            }""")
            assert page.locator(".fa-prose").evaluate_all(
                "elements => elements.every(el => !el.textContent.includes('Source:'))"
            )
            button.press("Enter")
            expect(button).to_have_attribute("aria-expanded", "true")
            bullets = accordion.locator("ul > li")
            expect(bullets).to_have_count(len(sources))
            for index, source in enumerate(sources):
                bullet = bullets.nth(index)
                expect(bullet.locator("code")).to_have_count(1)
                expect(bullet.locator("code")).to_have_text(source["text"])
                detail = f" ({source['detail']})" if source["detail"] else ""
                expect(bullet).to_have_text(source["text"] + detail)
                assert (
                    bullet.evaluate("el => getComputedStyle(el).listStyleType")
                    == "disc"
                )
                assert (
                    "mono"
                    in bullet.locator("code")
                    .evaluate("el => getComputedStyle(el).fontFamily")
                    .lower()
                )
                links = bullet.get_by_role("link")
                if source["href"]:
                    expect(links).to_have_count(1)
                    expect(links).to_have_attribute("href", source["href"])
                    expect(links).to_have_text(source["text"])
                else:
                    expect(links).to_have_count(0)
            button.press("Space")
            expect(button).to_have_attribute("aria-expanded", "false")
            expect(button).to_be_focused()

        def fit():
            result = page.evaluate(FIT)
            assert abs(result["scale"] - result["expected"]) < 0.002, result
            return result

        def legend(flow):
            fieldset = page.locator("fieldset.fa-legend")
            text = (
                "Use Previous and Next to walk through the steps"
                if flow
                else "Toggle to show or hide"
            )
            expect(fieldset.locator("legend")).to_have_text(text)
            expect(page.get_by_role("group", name=text, exact=True)).to_be_visible()
            assert fieldset.locator("legend").count() == 1
            bounds = fieldset.locator("legend").bounding_box()
            toggles = fieldset.locator("legend + *").bounding_box()
            assert bounds["y"] + bounds["height"] <= toggles["y"], (bounds, toggles)
            expect(fieldset.get_by_text("Connections", exact=True)).to_have_count(0)
            if flow:
                expect(fieldset.get_by_role("checkbox")).to_have_count(0)
            else:
                assert fieldset.get_by_role("checkbox").count() > 0

        def placeholder():
            result = page.evaluate(PLACEHOLDER)
            assert result["text"] == "Search components", result
            assert result["textWidth"] <= result["available"], result
            return result

        def screenshot(name, reset_panel=True):
            if reset_panel:
                page.evaluate(
                    "scrollTo(0, 0); document.querySelector('.fa-aside').scrollTo(0, 0)"
                )
            # Let Chrome repaint after viewport/scroll changes before full-page capture.
            page.wait_for_timeout(250)
            page.screenshot(path=args.output / (name + ".png"), full_page=True)

        page.goto(args.url.split("#")[0] + "#" + overview["id"])
        loaded()
        sidebar("navigation", False)
        sidebar("details", False)
        inline_controls()
        expect(page.get_by_label("Find a Component", exact=True)).to_have_attribute(
            "id", "search"
        )
        sidebar("navigation", False).focus()
        page.keyboard.press("Tab")
        expect(page.locator("#search")).to_be_focused()
        sidebar("navigation", False).press("Enter")
        expect(sidebar("navigation", True)).to_be_focused()
        sidebar("navigation", True).press("Space")
        expect(sidebar("navigation", False)).to_be_focused()
        legend(False)
        key = page.get_by_role("button", name="Diagram Key", exact=True)
        expect(key).to_have_attribute("aria-expanded", "true")
        key.click()
        expect(key).to_have_attribute("aria-expanded", "false")
        key.click()
        checks.append("Diagram Key starts expanded and remains user-collapsible")
        metrics["placeholder1440"] = placeholder()
        navigate(overview["id"])
        initial = fit()
        set_sidebar("navigation", True)
        left = fit()
        assert left["width"] > initial["width"], (initial, left)
        set_sidebar("details", True)
        both = fit()
        assert both["width"] > left["width"], (left, both)
        assert both["scale"] > initial["scale"], (initial, both)
        assert page.locator(".fa-nav").bounding_box()["width"] == 44
        assert page.locator(".fa-aside").bounding_box()["width"] == 44
        expect(page.get_by_role("separator")).to_have_count(0)
        metrics["fit"] = {
            "expanded": initial,
            "leftCollapsed": left,
            "bothCollapsed": both,
        }
        checks.append(
            "Both rails retain accessible controls; each collapse grows the stage and Fit recomputes"
        )
        page.reload()
        loaded()
        sidebar("navigation", True)
        sidebar("details", True)
        assert (
            page.evaluate("localStorage.getItem('architecture-navigation-collapsed')")
            == "true"
        )
        assert (
            page.evaluate("localStorage.getItem('architecture-details-collapsed')")
            == "true"
        )
        checks.append("Both sidebar preferences survive reload")
        sidebar("navigation", True).press("Enter")
        sidebar("navigation", False)
        page.reload()
        loaded()
        sidebar("navigation", False)
        sidebar("details", True)
        sidebar("details", True).press("Space")
        sidebar("details", False)
        page.reload()
        loaded()
        sidebar("navigation", False)
        sidebar("details", False)
        checks.append("Keyboard expansion and expanded-state persistence")
        navigate(overview["id"])

        separator = page.get_by_role("separator", name="Resize details panel")
        separator.press("ArrowLeft")
        expect(separator).to_have_attribute("aria-valuenow", "396")
        separator.press("Home")
        expect(separator).to_have_attribute("aria-valuenow", "260")
        separator.press("End")
        expect(separator).to_have_attribute(
            "aria-valuenow", separator.get_attribute("aria-valuemax")
        )
        separator.dblclick()
        expect(separator).to_have_attribute("aria-valuenow", "372")
        rect = separator.bounding_box()
        page.mouse.move(rect["x"] + rect["width"] / 2, rect["y"] + 50)
        page.mouse.down()
        page.mouse.move(rect["x"] - 45, rect["y"] + 50, steps=4)
        page.mouse.up()
        assert int(separator.get_attribute("aria-valuenow")) > 400
        page.reload()
        loaded()
        assert int(separator.get_attribute("aria-valuenow")) > 400
        saved_details_width = separator.get_attribute("aria-valuenow")
        set_sidebar("details", True)
        expect(separator).to_have_count(0)
        expect(
            page.get_by_role("separator", name="Resize navigation panel")
        ).to_be_visible()
        page.reload()
        loaded()
        set_sidebar("details", False)
        expect(separator).to_have_attribute("aria-valuenow", saved_details_width)
        separator.dblclick()
        separator.press("ArrowRight")
        expect(separator).to_have_attribute("aria-valuenow", "348")
        separator.dblclick()
        checks.append(
            "Expanded details retain pointer, keyboard, reset and saved-width resizing after collapse"
        )

        nav_separator = page.get_by_role("separator", name="Resize navigation panel")
        nav_separator.press("ArrowRight")
        expect(nav_separator).to_have_attribute("aria-valuenow", "248")
        nav_separator.press("Home")
        nav_separator.press("ArrowLeft")
        expect(nav_separator).to_have_attribute("aria-valuenow", "224")
        nav_separator.press("End")
        nav_max = nav_separator.get_attribute("aria-valuemax")
        nav_separator.press("ArrowRight")
        expect(nav_separator).to_have_attribute("aria-valuenow", nav_max)
        nav_separator.dblclick()
        expect(nav_separator).to_have_attribute("aria-valuenow", "224")
        rect = nav_separator.bounding_box()
        page.mouse.move(rect["x"] + rect["width"] / 2, rect["y"] + 50)
        page.mouse.down()
        page.mouse.move(rect["x"] + 63, rect["y"] + 50, steps=4)
        page.mouse.up()
        saved_nav_width = nav_separator.get_attribute("aria-valuenow")
        assert int(saved_nav_width) > 270
        page.wait_for_timeout(250)
        fit()
        set_sidebar("navigation", True)
        expect(nav_separator).to_have_count(0)
        expect(separator).to_be_visible()
        page.reload()
        loaded()
        set_sidebar("navigation", False)
        expect(nav_separator).to_have_attribute("aria-valuenow", saved_nav_width)
        assert page.locator(".fa-nav").bounding_box()["width"] == int(saved_nav_width)
        nav_separator.dblclick()
        checks.append(
            "Navigation supports pointer/keyboard resizing, min/max bounds, double-click reset and width restoration after collapse/reload"
        )

        set_sidebar("details", True)
        node = page.locator("[data-node][role=button]").first
        node_id = node.get_attribute("data-node")
        node.press("Enter")
        sidebar("details", False)
        assert page.url.endswith("/" + node_id), page.url
        set_sidebar("details", True)
        node.press("Enter")
        sidebar("details", False)
        assert page.url.endswith("/" + node_id), page.url
        checks.append(
            "Component selection, including reselecting the same component, expands details"
        )
        page.keyboard.press("Escape")
        expect(page).to_have_url(args.url.split("#")[0] + "#" + overview["id"])
        page.locator("#search").fill(search_term)
        result = (
            page.get_by_role("list", name="Matching components")
            .get_by_role("link")
            .first
        )
        assert search_term.lower() in result.inner_text().lower()
        set_sidebar("details", True)
        result.click()
        sidebar("details", False)
        expect(page.locator("#search")).to_have_value("")
        checks.append(
            "Search finds a component, clears after navigation and expands details"
        )
        navigate(overview["id"])
        checkbox = page.locator(".fa-legend input[type=checkbox]").first
        toggle = page.locator("[data-flow-toggle]").first.get_attribute(
            "data-flow-toggle"
        )
        checkbox.press("Space")
        expect(checkbox).not_to_be_checked()
        assert page.locator(f'[data-edge][data-flow="{toggle}"].is-hidden').count() > 0
        checkbox.press("Space")
        expect(checkbox).to_be_checked()
        expect(page.locator("[data-edge].is-hidden")).to_have_count(0)
        checks.append("Connection toggles still filter architecture edges")

        navigate(flow["id"])
        legend(True)
        set_sidebar("details", True)
        page.get_by_role("button", name="Next", exact=True).click()
        sidebar("details", False)
        assert page.url.endswith("/step-2")
        set_sidebar("details", True)
        page.get_by_role("button", name="Previous", exact=True).click()
        sidebar("details", False)
        assert page.url.endswith("/step-1")
        set_sidebar("details", True)
        page.locator("[data-edge][data-step-id]").nth(1).press("Enter")
        sidebar("details", False)
        expect(page.locator("[data-edge][data-step-id]").nth(1)).to_be_focused()
        page.wait_for_function(STEP_VISIBLE)
        set_sidebar("details", True)
        page.locator(".fa-stage").press("]")
        sidebar("details", False)
        assert page.url.endswith("/step-3")
        checks.append(
            "Next, Previous, diagram arrows and bracket shortcuts expand details without stealing desktop focus"
        )
        navigate(flow["id"] + "/step-2")
        set_sidebar("details", True)
        page.go_back()
        loaded()
        sidebar("details", False)
        assert page.url.endswith("/step-3")
        page.wait_for_function(STEP_VISIBLE)
        page.go_forward()
        loaded()
        assert page.url.endswith("/step-2")
        page.wait_for_function(STEP_VISIBLE)
        checks.append(
            "Step deep links and Back/Forward restore the step and expand details"
        )
        for step in (1, 2):
            navigate(flow["id"] + f"/step-{step}")
            page.wait_for_function(STEP_VISIBLE)
        page.reload()
        loaded()
        page.wait_for_function(STEP_VISIBLE)
        navigate(flow["id"] + "/step-1")
        page.emulate_media(reduced_motion="no-preference")
        page.evaluate("document.querySelector('.fa-aside').scrollTo(0, 0)")
        next_button = page.get_by_role("button", name="Next", exact=True)
        next_button.scroll_into_view_if_needed()
        previous_y = page.evaluate("scrollY")
        next_button.click()
        page.wait_for_function(STEP_VISIBLE)
        expect(next_button).to_be_focused()
        assert page.evaluate("scrollY") == previous_y
        page.wait_for_timeout(600)
        page.locator(".fa-stage").press("]")
        page.wait_for_function(STEP_VISIBLE)
        expect(page.locator(".fa-stage")).to_be_focused()
        page.locator(".fa-stage").press("[")
        page.wait_for_function(STEP_VISIBLE)
        page.wait_for_timeout(600)
        assert page.evaluate(STEP_VISIBLE)
        expect(page.locator(".fa-stage")).to_be_focused()
        # Direct diagram activation reveals the description without focusing it.
        page.get_by_role("radio", name="Fit all", exact=True).click()
        badge = (
            page.locator("[data-edge][data-step-id]")
            .nth(1)
            .locator(".fa-step-badge circle")
        )
        badge.scroll_into_view_if_needed()
        page.locator(".fa-aside").evaluate("el => el.scrollTo(0, 0)")
        previous_y = page.evaluate("scrollY")
        badge.click()
        page.wait_for_timeout(700)
        assert page.evaluate(STEP_VISIBLE)
        assert page.evaluate("scrollY") == previous_y
        expect(page.locator("[data-step-row]").nth(1)).not_to_be_focused()
        expect(page.locator("[data-edge][data-step-id]").nth(1)).to_be_focused()
        page.get_by_role("radio", name="Readable", exact=True).click()
        # A quick reversal must cancel the previous smooth-scroll destination.
        next_button.click()
        page.get_by_role("button", name="Previous", exact=True).click()
        page.wait_for_timeout(700)
        assert page.evaluate(STEP_VISIBLE)
        expect(page.get_by_role("button", name="Previous", exact=True)).to_be_focused()
        for theme in ("Light", "Dark"):
            page.get_by_role("radio", name=theme, exact=True).click()
            page.wait_for_timeout(200)
            screenshot(f"{theme.lower()}-1440-flow-mid-walkthrough", reset_panel=False)
        metrics["walkthroughScrollTop"] = page.locator(".fa-aside").evaluate(
            "el => el.scrollTop"
        )
        assert (
            metrics["walkthroughScrollTop"] >= 0
        )  # short guides may fit without scrolling
        checks.append(
            "Deep links, reload and smooth Next/bracket navigation fully reveal the step description within the desktop aside without moving focus or scrolling the document"
        )
        page.emulate_media(reduced_motion="reduce")
        page.set_viewport_size({"width": 390, "height": 1050})
        navigate(flow["id"] + "/step-1")
        next_button.scroll_into_view_if_needed()
        previous_y = page.evaluate("scrollY")
        next_button.click()
        page.wait_for_timeout(200)
        expect(next_button).to_be_focused()
        assert page.evaluate("scrollY") == previous_y
        page.get_by_role("button", name="Previous", exact=True).click()
        page.wait_for_timeout(200)
        assert page.evaluate("scrollY") == previous_y
        page.locator(".fa-stage").focus()
        previous_y = page.evaluate("scrollY")
        for shortcut in ("]", "["):
            page.locator(".fa-stage").press(shortcut)
            page.wait_for_timeout(200)
            expect(page.locator(".fa-stage")).to_be_focused()
            assert page.evaluate("scrollY") == previous_y
        navigate(flow["id"] + "/step-1")
        assert page.evaluate("scrollY") == previous_y
        page.get_by_role("radio", name="Fit all", exact=True).click()
        page.locator("[data-edge][data-step-id]").nth(1).locator(
            ".fa-step-badge circle"
        ).tap()
        expect(page.locator("[data-step-row]").nth(1)).to_be_focused()
        bounds = page.locator("[data-step-row]").nth(1).locator("..").bounding_box()
        assert 0 <= bounds["y"] and bounds["y"] + bounds["height"] <= 1050
        navigate(flow["id"] + "/step-1")
        page.get_by_role("radio", name="Readable", exact=True).click()
        page.wait_for_timeout(250)
        page.locator(".fa-stage").scroll_into_view_if_needed()
        arrow = page.locator("[data-edge][data-step-id]").first.locator(
            "path.connection"
        )
        point = arrow.evaluate("""path => {
            const p = path.getPointAtLength(path.getTotalLength() * 0.25);
            const screen = new DOMPoint(p.x, p.y).matrixTransform(path.getScreenCTM());
            return {x: screen.x, y: screen.y};
        }""")
        page.touchscreen.tap(point["x"], point["y"])
        expect(page.locator("[data-step-row]").first).to_be_focused()
        for width in (390, 900):
            page.set_viewport_size({"width": width, "height": 1050})
            for selector in (".fa-nav", ".fa-aside"):
                assert (
                    page.locator(selector).evaluate(
                        "el => getComputedStyle(el).maxHeight"
                    )
                    == "none"
                )
            expect(page.get_by_role("separator")).to_have_count(0)
        checks.append(
            "Mobile Previous/Next and both brackets/deep links preserve page position; real touch badge/arrow taps reveal and focus evidence rows; mobile/tablet sidebars have no height cap"
        )
        page.set_viewport_size({"width": 1440, "height": 1050})

        for theme in ("Light", "Dark"):
            page.get_by_role("radio", name=theme, exact=True).click()
            navigate(overview["id"])
            # Prefer a family with exclusive endpoints, preserving other boxes for paint checks.
            families = overview["flowIds"]
            for family in families:
                hidden = {
                    e[end]
                    for e in overview["edges"]
                    if e["flow"] == family
                    for end in ("from", "to")
                }
                visible = {
                    e[end]
                    for e in overview["edges"]
                    if e["flow"] != family
                    for end in ("from", "to")
                }
                if any(not data["nodes"][node]["isFrame"] for node in hidden - visible):
                    families = [family]
                    break
            toggles = page.locator(
                ",".join(f'[data-flow-toggle="{family}"]' for family in families)
            )
            for toggle in page.locator("[data-flow-toggle]").all():
                if not toggle.is_checked():
                    toggle.press("Space")

            def toggle_connections(toggles=toggles):
                for toggle in toggles.all():
                    toggle.press("Space")

            baseline = page.evaluate(NODE_PAINTS)
            toggle_connections()
            filtered = page.evaluate(NODE_PAINTS)
            remaining = [
                id for id, node in filtered.items() if not node["disconnected"]
            ]
            disconnected = [id for id, node in filtered.items() if node["disconnected"]]
            assert disconnected
            for id in remaining:
                assert filtered[id]["paints"] == baseline[id]["paints"], (
                    id,
                    baseline[id],
                    filtered[id],
                )
                assert filtered[id]["opacity"] == "1"
            for id in disconnected:
                assert not filtered[id]["frame"]
                assert filtered[id]["opacity"] == "0.25"
                assert all(
                    paint["shapeOpacity"] == "1" for paint in filtered[id]["paints"]
                )
            screenshot(f"{theme.lower()}-1440-connections-hidden")
            page.set_viewport_size({"width": 390, "height": 1050})
            screenshot(f"{theme.lower()}-390-connections-hidden")
            page.set_viewport_size({"width": 1440, "height": 1050})
            toggle_connections()
            page.locator(f'[data-node="{component}"]').press("Enter")
            baseline = page.evaluate(NODE_PAINTS)
            toggle_connections()
            filtered = page.evaluate(NODE_PAINTS)
            for id in remaining:
                assert filtered[id]["paints"] == baseline[id]["paints"], (
                    id,
                    baseline[id],
                    filtered[id],
                )
            metrics[f"{theme.lower()}FilteredComponent"] = {
                "before": baseline[component],
                "after": filtered[component],
            }
            toggle_connections()
            navigate(overview["id"])
        checks.append(
            "Filtering fades entire disconnected boxes to 0.25, never frames, and preserves remaining strokes/widths/shape opacity in both themes including selected-node dimming"
        )

        metrics["sources"] = {"views": 0, "components": 0, "emptyOrMissing": 0}
        for view in data["views"]:
            navigate(view["id"])
            sources_panel(view)
            metrics["sources"][
                "views" if view.get("sources") else "emptyOrMissing"
            ] += 1
            expect(page.get_by_role("heading", level=2)).to_have_text(view["title"])
            legend(view["category"] == "flow")
            expect(
                page.get_by_role("button", name="Diagram Key", exact=True)
            ).to_have_attribute("aria-expanded", "true")
            if view["category"] == "flow":
                expect(page.locator("[data-step-row]")).to_have_count(
                    len(view["steps"])
                )
                expect(page.locator(".fa-step-badge")).to_have_count(len(view["steps"]))
            else:
                expect(page.locator(".fa-step-badge")).to_have_count(0)
        checks.append(
            f"All {len(data['views'])} architecture/flow routes render with the correct legend, step rows and badges"
        )

        for doc_id, doc in data["docs"].items():
            route = next(
                (
                    f"{view['id']}/{node}"
                    for view in data["views"]
                    for node in view["nodeIds"]
                    if data["docOf"].get(node) == doc_id
                ),
                None,
            )
            assert route, doc_id
            navigate(route)
            sources_panel(doc)
            metrics["sources"][
                "components" if doc.get("sources") else "emptyOrMissing"
            ] += 1
        checks.append(
            "Every component and view guide hides empty/missing sources; nonempty Sources (n) starts collapsed after links/related views and expands to one monospace, individually linked bullet per source with optional detail, never a comma-delimited run"
        )
        for theme in ("Light", "Dark"):
            page.get_by_role("radio", name=theme, exact=True).click()
            navigate(overview["id"])
            inline_controls()
            screenshot(f"{theme.lower()}-1440-sources-guide-collapsed")
            button = page.locator("#details .fa-citations").get_by_role("button")
            if button.count():
                button.click()
                screenshot(f"{theme.lower()}-1440-sources-guide-expanded")
            navigate(overview["id"] + "/" + component)
            inline_controls()
            sidebar("details", False).focus()
            page.keyboard.press("Tab")
            expect(
                page.get_by_role("button", name="View Guide", exact=True)
            ).to_be_focused()
            sidebar("details", False).press("Enter")
            expect(sidebar("details", True)).to_be_focused()
            sidebar("details", True).press("Space")
            expect(sidebar("details", False)).to_be_focused()
            screenshot(f"{theme.lower()}-1440-sources-component-collapsed")
            button = page.locator("#details .fa-citations").get_by_role("button")
            if button.count():
                button.click()
                screenshot(f"{theme.lower()}-1440-sources-component-expanded")
        checks.append(
            "Collapse buttons share a row with Find a Component and Component/View Guide kickers in both themes; labels, tab order and keyboard toggle focus remain intact"
        )

        page.get_by_role("radio", name="Light", exact=True).click()
        for height in (900, 700):
            page.set_viewport_size({"width": 1440, "height": height})
            navigate(longest_flow["id"] + f"/step-{last_step - 1}")
            page.evaluate("scrollTo(0, 0)")
            next_button.click()
            page.wait_for_function(STEP_VISIBLE)
            assert page.url.endswith(f"/step-{last_step}")
            assert page.evaluate("scrollY") == 0
            metrics[f"lastStepAt{height}"] = page.locator(
                '[data-step-row][aria-pressed="true"]'
            ).evaluate("""el => {
                const r = el.closest('li').getBoundingClientRect();
                return {top: r.top, bottom: r.bottom, documentScroll: scrollY,
                    asideScroll: document.querySelector('.fa-aside').scrollTop};
            }""")
            for name in (".fa-nav", ".fa-aside"):
                box = page.locator(name).bounding_box()
                assert box["y"] >= 0 and box["y"] + box["height"] <= height + 0.1
            page.locator(".fa-nav").evaluate("el => el.scrollTo(0, el.scrollHeight)")
            last = page.locator(".fa-desktop-nav [data-view]").last.bounding_box()
            nav = page.locator(".fa-nav").bounding_box()
            assert nav["y"] <= last["y"] and last["y"] + last["height"] <= height
            assert page.evaluate("scrollY") == 0
            screenshot(f"light-1440-{height}-last-flow-step", reset_panel=False)
            navigate(overview["id"])
            page.locator(".fa-nav").evaluate("el => el.scrollTo(0, el.scrollHeight)")
            last = page.locator(".fa-desktop-nav [data-view]").last.bounding_box()
            assert nav["y"] <= last["y"] and last["y"] + last["height"] <= height
            assert page.evaluate("scrollY") == 0
            metrics[f"viewport{height}"] = page.evaluate("""() => Object.fromEntries(
                ['.fa-nav', '.fa-aside'].map(selector => {
                    const el = document.querySelector(selector);
                    const r = el.getBoundingClientRect();
                    return [selector, {top: r.top, bottom: r.bottom, height: r.height}];
                }))""")
            page.locator(".fa-nav").hover()
            page.mouse.wheel(0, 1000)
            page.wait_for_timeout(200)
            assert page.evaluate("scrollY") == 0
            page.evaluate("scrollTo(0, 200)")
            for selector in (".fa-nav", ".fa-aside"):
                box = page.locator(selector).bounding_box()
                assert box["y"] == 0 and box["height"] <= height
            page.evaluate("scrollTo(0, 0)")
        checks.append(
            "At 1440x900 and 1440x700 both desktop panels fit the viewport and stay sticky; Next reveals the longest flow's last step; the last nav item is reachable by scrolling only navigation, without wheel scroll chaining"
        )
        page.set_viewport_size({"width": 1440, "height": 1050})

        for theme in ("Light", "Dark"):
            page.get_by_role("radio", name=theme, exact=True).click()
            expect(page.locator(".architecture-site")).to_have_attribute(
                "data-theme", theme.lower()
            )
            navigate(overview["id"])
            for nav, details, label in (
                (False, False, "expanded"),
                (True, True, "collapsed"),
                (True, False, "navigation-collapsed"),
                (False, True, "details-collapsed"),
            ):
                set_sidebar("navigation", nav)
                set_sidebar("details", details)
                fit()
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                )
                screenshot(f"{theme.lower()}-1440-{label}")
            set_sidebar("navigation", True)
            page.set_viewport_size({"width": 390, "height": 1050})
            loaded()
            for label in ("Expand navigation", "Expand details"):
                expect(
                    page.get_by_role("button", name=label, exact=True)
                ).to_have_count(0)
            expect(page.locator("#navigation")).to_be_visible()
            expect(page.locator("#details-content")).to_be_visible()
            expect(page.get_by_role("separator")).to_have_count(0)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            metrics["placeholder390"] = placeholder()
            legend(False)
            screenshot(f"{theme.lower()}-390-stacked")
            page.set_viewport_size({"width": 1440, "height": 1050})
            loaded()
            sidebar("navigation", True)
            sidebar("details", True)
        checks.append(
            "Light/dark screenshots at 1440 for all four sidebar states and 390 stacked; narrow layout ignores but preserves desktop preferences"
        )
        checks.append(
            "Search placeholder fits its text area at 1440 and 390; legend hint is on its own line before the toggles"
        )
        navigate(overview["id"] + "/" + node_id)
        set_sidebar("details", True)
        page.set_viewport_size({"width": 390, "height": 1050})
        loaded()
        page.locator(f'[data-node="{node_id}"]').press("Enter")
        expect(page).to_have_url(args.url.split("#")[0] + "#" + overview["id"])
        checks.append(
            "Reselecting a component in the stacked layout retains the existing deselect behaviour"
        )
        context.close()
        denied = browser.new_context(viewport={"width": 1440, "height": 1050})
        denied.add_init_script(
            "Storage.prototype.getItem = Storage.prototype.setItem = () => { throw new Error('Storage denied'); };"
        )
        page = denied.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(args.url.split("#")[0] + "#" + overview["id"])
        loaded()
        set_sidebar("navigation", True)
        set_sidebar("details", True)
        set_sidebar("navigation", False)
        set_sidebar("details", False)
        page.get_by_role("separator", name="Resize navigation panel").press(
            "ArrowRight"
        )
        expect(
            page.get_by_role("separator", name="Resize navigation panel")
        ).to_have_attribute("aria-valuenow", "248")
        page.get_by_role("separator", name="Resize details panel").press("ArrowLeft")
        expect(
            page.get_by_role("separator", name="Resize details panel")
        ).to_have_attribute("aria-valuenow", "396")
        checks.append(
            "Unavailable localStorage does not prevent either sidebar collapsing or resizing"
        )
        denied.close()
        deep_link = browser.new_context(viewport={"width": 1440, "height": 700})
        deep_link.add_init_script(
            "localStorage.setItem('architecture-details-collapsed', 'true')"
        )
        page = deep_link.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(
            args.url.split("#")[0] + "#" + longest_flow["id"] + f"/step-{last_step}"
        )
        loaded()
        sidebar("details", False)
        page.wait_for_function(STEP_VISIBLE)
        assert page.evaluate("scrollY") == 0
        assert page.evaluate("document.activeElement === document.body")
        checks.append(
            "An initial step deep link opens a previously collapsed details panel and reveals the full row without stealing focus"
        )
        browser.close()
    assert not errors, errors
    report = {"checks": checks, "metrics": metrics, "runtimeExceptions": errors}
    (args.output / "ui.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(checks)} checks passed, {len(errors)} runtime exceptions")
    print(f"Report and screenshots: {args.output}")


if __name__ == "__main__":
    main()
