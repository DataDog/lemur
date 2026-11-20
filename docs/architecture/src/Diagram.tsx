import { Button } from '@druids/ui/form/Button';
import { Checkbox } from '@druids/ui/form/Checkbox';
import { ToggleButtons } from '@druids/ui/form/ToggleButtons';
import { Accordion } from '@druids/ui/layout/Accordion';
import { Flex } from '@druids/ui/layout/Flex';
import { Panel } from '@druids/ui/layout/Panel';
import { Spacing } from '@druids/ui/layout/Spacing';
import { Link } from '@druids/ui/nav/Link';
import { Text } from '@druids/ui/typography/Text';
import * as React from 'react';
import ResizeObserver from 'resize-observer-polyfill';

import { FA_STEP_COUNTER_MAX, model, nodeLabel, routeHash } from './model';
import { trackAction } from './rum';
import type { ArchitectureView } from './types';

type Props = {
    view: ArchitectureView;
    selected: string | null;
    onSelect: (id: string | null) => void;
    activeStep: string | null;
    selectedStep: string | null;
    stepRequest: number;
    onStepHover: (id: string | null) => void;
    onStepSelect: (id: string) => void;
    onStepInspect: (id: string) => void;
};

export function Diagram({
    view,
    selected,
    onSelect,
    activeStep,
    selectedStep,
    stepRequest,
    onStepHover,
    onStepSelect,
    onStepInspect,
}: Props): React.ReactElement {
    const stage = React.useRef<HTMLElement>(null);
    const board = React.useRef<HTMLElement>(null);
    const [hidden, setHidden] = React.useState<Set<string>>(new Set());
    const [hoveredNode, setHoveredNode] = React.useState<string | null>(null);
    const [zoom, setZoom] = React.useState(1);
    const [mode, setMode] = React.useState<'fit' | 'readable'>(
        view.category === 'flow' ? 'readable' : 'fit',
    );
    const drag = React.useRef<{
        x: number;
        y: number;
        left: number;
        top: number;
    } | null>(null);
    const dragged = React.useRef(false);
    const stepIndex = view.steps.findIndex((step) => step.id === selectedStep);
    const moveStep = (offset: number) => {
        const step = view.steps[stepIndex + offset];
        if (step) {
            onStepSelect(step.id);
        }
    };
    // SVG is sanitized and semantically annotated by the generator, never decoded in the browser.
    const markup = React.useMemo(
        () => ({ __html: model.diagrams[view.id] }),
        [view.id],
    );

    React.useLayoutEffect(() => {
        const host = stage.current;
        const content = board.current;
        const svg = content?.querySelector('svg');
        if (!host || !content || !svg) {
            return;
        }
        const resize = () => {
            const box = svg.viewBox.baseVal;
            const fit = Math.min(
                (host.clientWidth - 48) / box.width,
                (host.clientHeight - 48) / box.height,
            );
            const scale = Math.max(
                0.01,
                (mode === 'fit' ? fit : Math.max(0.85, fit)) * zoom,
            );
            content.style.width = `${box.width * scale}px`;
            content.style.setProperty(
                '--fa-step-counter-scale',
                String(Math.min(Math.max(1 / scale, 1), FA_STEP_COUNTER_MAX)),
            );
        };
        resize();
        const observer = new ResizeObserver(resize);
        observer.observe(host);
        return () => observer.disconnect();
    }, [mode, zoom, view.id]);

    React.useEffect(() => {
        const host = stage.current;
        if (!host) {
            return;
        }
        const wheel = (event: WheelEvent) => {
            if (event.ctrlKey || event.metaKey) {
                event.preventDefault();
                setZoom((current) =>
                    Math.max(
                        0.25,
                        Math.min(6, current * Math.exp(-event.deltaY * 0.005)),
                    ),
                );
            }
        };
        host.addEventListener('wheel', wheel, { passive: false });
        return () => host.removeEventListener('wheel', wheel);
    }, []);

    React.useLayoutEffect(() => {
        const focus = hoveredNode ?? selected;
        const connected = new Set(focus ? [focus] : []);
        const live = new Set<string>();
        for (const edge of view.edges) {
            if (!hidden.has(edge.flow)) {
                live.add(edge.from);
                live.add(edge.to);
            }
            // Keep hover/selection dimming stable when connection filters change.
            if (edge.from === focus || edge.to === focus) {
                connected.add(edge.from);
                connected.add(edge.to);
            }
        }
        for (const node of board.current?.querySelectorAll<SVGGElement>(
            '[data-node]',
        ) ?? []) {
            const id = node.dataset.node ?? '';
            const selectable = Boolean(model.docOf[id]);
            if (selectable) {
                node.setAttribute('tabindex', '0');
                node.setAttribute('role', 'button');
                node.setAttribute('aria-label', `Details: ${nodeLabel(id)}`);
                node.setAttribute('aria-pressed', String(id === selected));
            }
            node.classList.toggle('is-selected', id === selected);
            node.classList.toggle(
                'is-muted',
                !model.nodes[id]?.isFrame &&
                    Boolean(focus) &&
                    !connected.has(id),
            );
            node.classList.toggle(
                'is-disconnected',
                !model.nodes[id]?.isFrame && hidden.size > 0 && !live.has(id),
            );
        }
        for (const edge of board.current?.querySelectorAll<SVGGElement>(
            '[data-edge]',
        ) ?? []) {
            const step = view.steps.find(
                (item) => item.id === edge.dataset.stepId,
            );
            if (step) {
                edge.setAttribute('tabindex', '0');
                edge.setAttribute('role', 'button');
                edge.setAttribute(
                    'aria-label',
                    `Step ${step.number}: ${step.label}`,
                );
                edge.setAttribute(
                    'aria-pressed',
                    String(step.id === selectedStep),
                );
            }
            edge.classList.toggle(
                'is-hidden',
                view.category === 'architecture' &&
                    hidden.has(edge.dataset.flow ?? ''),
            );
            edge.classList.toggle(
                'is-active',
                Boolean(activeStep) && edge.dataset.stepId === activeStep,
            );
            edge.classList.toggle(
                'is-muted',
                activeStep
                    ? edge.dataset.stepId !== activeStep
                    : Boolean(focus) &&
                          edge.dataset.from !== focus &&
                          edge.dataset.to !== focus,
            );
        }
    }, [view, selected, selectedStep, hidden, activeStep, hoveredNode]);

    const centerStep = React.useCallback(() => {
        const edge = Array.from(
            board.current?.querySelectorAll<SVGGElement>('[data-edge]') ?? [],
        ).find((item) => item.dataset.stepId === selectedStep);
        const host = stage.current;
        const target = edge?.querySelector('.fa-step-badge circle') ?? edge;
        if (host && target) {
            const bounds = host.getBoundingClientRect();
            const item = target.getBoundingClientRect();
            // Scroll only the diagram, preserving zoom and the mobile evidence-list position.
            host.scrollBy({
                left:
                    item.left +
                    item.width / 2 -
                    bounds.left -
                    host.clientWidth / 2,
                top:
                    item.top +
                    item.height / 2 -
                    bounds.top -
                    host.clientHeight / 2,
                behavior: window.matchMedia('(prefers-reduced-motion: reduce)')
                    .matches
                    ? 'instant'
                    : 'smooth',
            });
        }
    }, [selectedStep]);

    React.useEffect(() => {
        const frame = requestAnimationFrame(centerStep);
        return () => cancelAnimationFrame(frame);
    }, [centerStep, stepRequest]);

    const selectTarget = (target: EventTarget) => {
        if (!(target instanceof Element) || dragged.current) {
            return;
        }
        const step = target.closest<SVGGElement>('[data-edge][data-step-id]')
            ?.dataset.stepId;
        if (step) {
            onStepInspect(step);
            return;
        }
        const node = target.closest<SVGGElement>('[data-node]');
        const id = node?.dataset.node;
        if (id && model.docOf[id]) {
            onSelect(selected === id ? null : id);
        }
    };

    const changeZoom = (factor: number) =>
        setZoom((current) => Math.max(0.25, Math.min(6, current * factor)));

    return (
        <>
            <Panel
                as="section"
                padding="none"
                borderRadius="md"
                ariaAttrs={{ 'aria-label': 'Interactive diagram' }}
            >
                <Flex gap="sm" wrap="wrap" padding="md" className="fa-toolbar">
                    <Button
                        label="−"
                        ariaLabel="Zoom out"
                        size="sm"
                        isDisabled={zoom <= 0.25}
                        onClick={() => changeZoom(0.8)}
                    />
                    <Button
                        label="+"
                        ariaLabel="Zoom in"
                        size="sm"
                        isDisabled={zoom >= 6}
                        onClick={() => changeZoom(1.25)}
                    />
                    <ToggleButtons<'fit' | 'readable', true>
                        aria-label="Diagram size"
                        size="sm"
                        canBeEmpty
                        isTitleCased={false}
                        value={zoom === 1 ? mode : null}
                        options={[
                            { value: 'fit', label: 'Fit all' },
                            { value: 'readable', label: 'Readable' },
                        ]}
                        onChange={(next) => {
                            setMode(next ?? mode);
                            setZoom(1);
                            stage.current?.scrollTo(0, 0);
                            if (next === 'readable') {
                                requestAnimationFrame(centerStep);
                            }
                        }}
                    />
                </Flex>
                <Spacing as="fieldset" padding="md" className="fa-legend">
                    <Text as="legend" size="sm" variant="secondary">
                        {view.category === 'flow'
                            ? 'Use Previous and Next to walk through the steps'
                            : 'Toggle to show or hide'}
                    </Text>
                    <Flex wrap="wrap" gap="md">
                        {view.flowIds.map((id) => {
                            const flow = model.legend.flows[id];
                            const label = (
                                <Flex gap="xs">
                                    <span
                                        className="fa-line"
                                        style={{
                                            borderColor: `var(--fa-flow-${id})`,
                                        }}
                                        aria-hidden="true"
                                    />
                                    <Text size="sm">{flow.label}</Text>
                                </Flex>
                            );
                            return view.category === 'flow' ? (
                                <React.Fragment key={id}>
                                    {label}
                                </React.Fragment>
                            ) : (
                                <Checkbox
                                    key={id}
                                    size="sm"
                                    isMultiline
                                    isChecked={!hidden.has(id)}
                                    label={label}
                                    dataAttrs={{ 'data-flow-toggle': id }}
                                    onChange={(event) => {
                                        const shown = event.target.checked;
                                        const next = new Set(hidden);
                                        if (shown) {
                                            next.delete(id);
                                        } else {
                                            next.add(id);
                                        }
                                        setHidden(next);
                                        trackAction('flow_toggled', {
                                            flow: id,
                                            shown,
                                            view: view.id,
                                        });
                                    }}
                                />
                            );
                        })}
                    </Flex>
                </Spacing>
                {stepIndex >= 0 && (
                    <Flex
                        gap="sm"
                        wrap="wrap"
                        padding="md"
                        className="fa-walkthrough"
                        aria-label="Flow walkthrough"
                    >
                        <Button
                            label="Previous"
                            size="sm"
                            isDisabled={stepIndex === 0}
                            onClick={() => moveStep(-1)}
                        />
                        <Text size="sm" weight="bold">
                            Step {stepIndex + 1} of {view.steps.length}
                        </Text>
                        <Button
                            label="Next"
                            size="sm"
                            isDisabled={stepIndex === view.steps.length - 1}
                            onClick={() => moveStep(1)}
                        />
                        <Text size="sm">{view.steps[stepIndex].label}</Text>
                    </Flex>
                )}
                <Text
                    as="div"
                    innerRef={stage}
                    tabIndex={0}
                    className="fa-stage"
                    aria-label={`Diagram. Arrow keys scroll; plus, minus, or Ctrl/Command and wheel zoom; Home fits all. Components and steps open with Enter or Space.${view.category === 'flow' ? ' Left and right brackets select the previous and next step.' : ''}`}
                    aria-keyshortcuts={
                        view.category === 'flow' ? '[ ]' : undefined
                    }
                    onKeyDown={(event) => {
                        if (event.target !== stage.current) {
                            return;
                        }
                        if (
                            view.category === 'flow' &&
                            (event.key === '[' || event.key === ']')
                        ) {
                            event.preventDefault();
                            moveStep(event.key === '[' ? -1 : 1);
                        }
                        if (event.key === '+' || event.key === '=') {
                            event.preventDefault();
                            changeZoom(1.25);
                        }
                        if (event.key === '-') {
                            event.preventDefault();
                            changeZoom(0.8);
                        }
                        if (event.key === 'Home') {
                            event.preventDefault();
                            setMode('fit');
                            setZoom(1);
                            stage.current?.scrollTo(0, 0);
                        }
                    }}
                    onPointerDown={(event) => {
                        if (event.button !== 0) {
                            return;
                        }
                        dragged.current = false;
                        drag.current = null;
                        if (event.pointerType === 'touch') {
                            return;
                        }
                        drag.current = {
                            x: event.clientX,
                            y: event.clientY,
                            left: event.currentTarget.scrollLeft,
                            top: event.currentTarget.scrollTop,
                        };
                    }}
                    onPointerMove={(event) => {
                        const start = drag.current;
                        if (event.buttons !== 1) {
                            drag.current = null;
                            return;
                        }
                        if (!start) {
                            return;
                        }
                        const dx = event.clientX - start.x;
                        const dy = event.clientY - start.y;
                        if (Math.abs(dx) + Math.abs(dy) > 5) {
                            dragged.current = true;
                            event.currentTarget.setPointerCapture(
                                event.pointerId,
                            );
                            event.currentTarget.scrollLeft = start.left - dx;
                            event.currentTarget.scrollTop = start.top - dy;
                        }
                    }}
                    onPointerUp={() => {
                        drag.current = null;
                    }}
                    onPointerCancel={() => {
                        drag.current = null;
                    }}
                    onLostPointerCapture={() => {
                        drag.current = null;
                    }}
                >
                    <Text
                        as="div"
                        innerRef={board}
                        className="fa-board"
                        // ESLint's react/no-danger skips custom components, so only oxlint needs this.
                        // oxlint-disable-next-line react/no-danger -- Sanitized generator SVG, never user input.
                        dangerouslySetInnerHTML={markup}
                        onClick={(event) => selectTarget(event.target)}
                        onKeyDown={(event) => {
                            if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault();
                                dragged.current = false;
                                selectTarget(event.target);
                            }
                        }}
                        onFocus={(event) => {
                            const edge = (
                                event.target as Element
                            ).closest<SVGGElement>('[data-edge]');
                            onStepHover(edge?.dataset.stepId ?? null);
                        }}
                        onBlur={() => onStepHover(null)}
                        onMouseOver={(event) => {
                            const node = (
                                event.target as Element
                            ).closest<SVGGElement>('[data-node]:not(.frame)')
                                ?.dataset.node;
                            setHoveredNode(node ?? null);
                            const id = (
                                event.target as Element
                            ).closest<SVGGElement>('[data-edge][data-step-id]')
                                ?.dataset.stepId;
                            onStepHover(id ?? null);
                        }}
                        onMouseLeave={() => {
                            onStepHover(null);
                            setHoveredNode(null);
                        }}
                    />
                </Text>
                <Accordion title="Diagram Key" size="sm" isOpenByDefault>
                    <Flex
                        gap="lg"
                        wrap="wrap"
                        padding="md"
                        alignItems="flex-start"
                    >
                        {[
                            ['Lines', model.legend.kinds, 'line'],
                            ['Boxes · Ownership', model.legend.shapes, 'shape'],
                            [
                                'Colour · Team Ownership',
                                model.legend.owners,
                                'owner',
                            ],
                            [
                                'Frames · Where It Runs',
                                model.legend.frames,
                                'frame',
                            ],
                        ]
                            .filter(([, entries]) =>
                                Object.keys(entries as object).length > 0,
                            )
                            .map(([title, entries, kind]) => (
                                <Flex
                                    key={title as string}
                                    direction="column"
                                    alignItems="stretch"
                                    gap="sm"
                                    className="fa-key-group"
                                >
                                    <Text weight="bold" size="sm">
                                        {title as string}
                                    </Text>
                                    {Object.entries(
                                        entries as Record<
                                            string,
                                            { label: string; color?: string }
                                        >,
                                    ).map(([id, item]) => (
                                        <Flex key={id} gap="sm">
                                            <span
                                                aria-hidden="true"
                                                className={`fa-key-${kind} fa-key-${kind}-${id}`}
                                                style={
                                                    kind === 'owner'
                                                        ? {
                                                              background: `var(--fa-owner-${id})`,
                                                          }
                                                        : undefined
                                                }
                                            />
                                            <Text size="sm">{item.label}</Text>
                                        </Flex>
                                    ))}
                                </Flex>
                            ))}
                    </Flex>
                </Accordion>
            </Panel>
            {view.category === 'architecture' && (
                <Accordion
                    title="Read the Diagram as a List"
                    size="md"
                    keepContentMounted
                >
                    <ul className="fa-connections">
                        {view.edges.map((edge) => (
                            <li key={edge.id} hidden={hidden.has(edge.flow)}>
                                <Link href={routeHash(view.id, edge.from)}>
                                    {nodeLabel(edge.from)}
                                </Link>{' '}
                                → {edge.label} →{' '}
                                <Link href={routeHash(view.id, edge.to)}>
                                    {nodeLabel(edge.to)}
                                </Link>
                            </li>
                        ))}
                    </ul>
                </Accordion>
            )}
        </>
    );
}
