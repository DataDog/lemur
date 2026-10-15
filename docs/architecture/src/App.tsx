import { SkipLink } from '@druids/ui/accessibility/SkipLink';
import { VisuallyHidden } from '@druids/ui/accessibility/VisuallyHidden';
import { Action } from '@druids/ui/form/Action';
import { Button } from '@druids/ui/form/Button';
import { InputSearch } from '@druids/ui/form/InputSearch';
import { Select } from '@druids/ui/form/Select';
import { ToggleButtons } from '@druids/ui/form/ToggleButtons';
import { BooksIcon } from '@druids/ui/icons/Books';
import { DashboardIcon } from '@druids/ui/icons/Dashboard';
import { LogsIcon } from '@druids/ui/icons/Logs';
import { PackageIcon } from '@druids/ui/icons/Package';
import { PanelLeftGrowIcon } from '@druids/ui/icons/PanelLeftGrow';
import { PanelLeftShrinkIcon } from '@druids/ui/icons/PanelLeftShrink';
import { PanelRightGrowIcon } from '@druids/ui/icons/PanelRightGrow';
import { PanelRightShrinkIcon } from '@druids/ui/icons/PanelRightShrink';
import { ServiceCatalogIcon } from '@druids/ui/icons/ServiceCatalog';
import { SourceControlRepositoryIcon } from '@druids/ui/icons/SourceControlRepository';
import { Accordion } from '@druids/ui/layout/Accordion';
import { Flex } from '@druids/ui/layout/Flex';
import { Grid } from '@druids/ui/layout/Grid';
import { Spacing } from '@druids/ui/layout/Spacing';
import { useGlobalThemePreference } from '@druids/ui/lib/color/use-global-theme-preference';
import { useTheme } from '@druids/ui/lib/color/use-theme';
import { Link } from '@druids/ui/nav/Link';
import { VerticalNav } from '@druids/ui/nav/VerticalNav';
import { List } from '@druids/ui/typography/List';
import { Text } from '@druids/ui/typography/Text';
import { Title } from '@druids/ui/typography/Title';
import * as React from 'react';
import ResizeObserver from 'resize-observer-polyfill';

import { Diagram } from './Diagram';
import { model, nodeLabel, readRoute, routeHash, stepRouteHash } from './model';
import { trackAction, trackView } from './rum';
import type { Category, Citation, Links, ThemePreference } from './types';

const linkTypes: Record<
    keyof Links,
    { label: string; icon: typeof BooksIcon }
> = {
    code: { label: 'Code', icon: SourceControlRepositoryIcon },
    wiki: { label: 'Wiki', icon: BooksIcon },
    k8s_chart: { label: 'Chart', icon: PackageIcon },
    datadog_service: { label: 'Service', icon: ServiceCatalogIcon },
    logs: { label: 'Logs', icon: LogsIcon },
    dashboard: { label: 'Dashboard', icon: DashboardIcon },
};

function LinkChips({ links }: { links: Links }): React.ReactElement {
    return (
        <Flex gap="sm" wrap="wrap" className="fa-links">
            {Object.entries(linkTypes).map(
                ([key, { label, icon: Icon }]) =>
                    links[key as keyof Links] && (
                        <Link
                            key={key}
                            href={links[key as keyof Links]}
                            className="fa-chip"
                            title={label}
                            ariaAttrs={{ 'aria-label': label }}
                        >
                            <Flex as="span" gap="xs">
                                <Icon title="" />
                                <span>{label}</span>
                            </Flex>
                        </Link>
                    ),
            )}
        </Flex>
    );
}

function Sources({
    sources,
}: {
    sources?: Citation[];
}): React.ReactElement | null {
    if (!sources?.length) {
        return null;
    }
    return (
        <Accordion
            title={`Sources (${sources.length})`}
            size="md"
            className="fa-citations"
        >
            <List hasMarginTop={false}>
                {sources.map((source, index) => (
                    <li key={index}>
                        {source.href ? (
                            <Link href={source.href}>
                                <Text as="code" isMonospace shouldInherit>
                                    {source.text}
                                </Text>
                            </Link>
                        ) : (
                            <Text as="code" isMonospace>
                                {source.text}
                            </Text>
                        )}
                        {source.detail && (
                            <Text variant="secondary"> ({source.detail})</Text>
                        )}
                    </li>
                ))}
            </List>
        </Accordion>
    );
}

function Prose({ html }: { html: string }): React.ReactElement {
    // Only the generator's raw-HTML-disabled, URL-validated Markdown enters this island.
    return (
        // eslint-disable-next-line react/no-danger -- Sanitized generator output, never user input.
        <div className="fa-prose" dangerouslySetInnerHTML={{ __html: html }} />
    );
}

function useCollapsedSidebar(
    key: string,
): [boolean, React.Dispatch<React.SetStateAction<boolean>>] {
    const [collapsed, setCollapsed] = React.useState(() => {
        try {
            return localStorage.getItem(key) === 'true';
        } catch {
            return false;
        }
    });
    React.useEffect(() => {
        try {
            localStorage.setItem(key, String(collapsed));
        } catch {
            /* Storage can be disabled in private browsing. */
        }
    }, [key, collapsed]);
    return [collapsed, setCollapsed];
}

function SidebarResizer({
    side,
    width,
    min,
    max,
    defaultWidth,
    onResize,
    onResizing,
}: {
    side: 'navigation' | 'details';
    width: number;
    min: number;
    max: number;
    defaultWidth: number;
    onResize: (width: number) => void;
    onResizing: (resizing: boolean) => void;
}): React.ReactElement {
    const start = React.useRef<{ x: number; width: number } | null>(null);
    const direction = side === 'navigation' ? 1 : -1;
    const finish = () => {
        start.current = null;
        onResizing(false);
    };
    return (
        <div
            className={`fa-resizer fa-resizer--${side}`}
            role="separator"
            tabIndex={0}
            aria-label={`Resize ${side} panel`}
            aria-controls={
                side === 'navigation' ? 'navigation' : 'details-content'
            }
            aria-orientation="vertical"
            aria-valuemin={min}
            aria-valuemax={max}
            aria-valuenow={width}
            onDoubleClick={() => onResize(defaultWidth)}
            onKeyDown={(event) => {
                if (
                    ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(
                        event.key,
                    )
                ) {
                    event.preventDefault();
                    onResize(
                        event.key === 'Home'
                            ? min
                            : event.key === 'End'
                              ? max
                              : width +
                                direction *
                                    (event.key === 'ArrowRight' ? 24 : -24),
                    );
                }
            }}
            onPointerDown={(event) => {
                if (event.button !== 0) {
                    return;
                }
                start.current = { x: event.clientX, width };
                event.currentTarget.setPointerCapture(event.pointerId);
                onResizing(true);
            }}
            onPointerMove={(event) => {
                if (start.current) {
                    onResize(
                        start.current.width +
                            direction * (event.clientX - start.current.x),
                    );
                }
            }}
            onPointerUp={finish}
            onPointerCancel={finish}
            onLostPointerCapture={finish}
        />
    );
}

export function App(): React.ReactElement {
    const header = React.useRef<HTMLElement>(null);
    const [headerHeight, setHeaderHeight] = React.useState(0);
    React.useLayoutEffect(() => {
        const element = header.current;
        if (!element) {
            return;
        }
        const measure = () =>
            setHeaderHeight(element.getBoundingClientRect().height);
        measure();
        const observer = new ResizeObserver(measure);
        observer.observe(element);
        return () => observer.disconnect();
    }, []);
    const [{ view, selected, step: stepSelection }, setRoute] =
        React.useState(readRoute);
    const [navigationCollapsed, setNavigationCollapsed] = useCollapsedSidebar(
        'architecture-navigation-collapsed',
    );
    const [detailsCollapsed, setDetailsCollapsed] = useCollapsedSidebar(
        'architecture-details-collapsed',
    );
    // Keep keyboard resizing: DraggablePane's react-split-pane separator has no public keyboard handlers.
    const [panelWidth, setPanelWidth] = React.useState(() => {
        try {
            return (
                Number(localStorage.getItem('architecture-panel-width')) || 372
            );
        } catch {
            return 372;
        }
    });
    const [navigationWidth, setNavigationWidth] = React.useState(() => {
        try {
            return (
                Number(localStorage.getItem('architecture-navigation-width')) ||
                224
            );
        } catch {
            return 224;
        }
    });
    const [navigationMax, setNavigationMax] = React.useState(420);
    const [panelMax, setPanelMax] = React.useState(650);
    const [resizing, setResizing] = React.useState(false);
    React.useEffect(() => {
        const resized = () => {
            if (window.innerWidth <= 1150) {
                return;
            }
            // Reserve diagram space even when both sidebars have been widened.
            const max = Math.max(
                260,
                Math.min(650, window.innerWidth - navigationWidth - 496),
            );
            const navMax = Math.max(
                224,
                Math.min(420, window.innerWidth - panelWidth - 496),
            );
            setPanelMax(max);
            setNavigationMax(navMax);
            setPanelWidth((width) => Math.max(260, Math.min(max, width)));
            setNavigationWidth((width) =>
                Math.max(224, Math.min(navMax, width)),
            );
        };
        resized();
        window.addEventListener('resize', resized);
        return () => window.removeEventListener('resize', resized);
    }, [navigationWidth, panelWidth]);
    React.useEffect(() => {
        try {
            localStorage.setItem(
                'architecture-panel-width',
                String(panelWidth),
            );
        } catch {
            /* Storage can be disabled in private browsing. */
        }
    }, [panelWidth]);
    React.useEffect(() => {
        try {
            localStorage.setItem(
                'architecture-navigation-width',
                String(navigationWidth),
            );
        } catch {
            /* Storage can be disabled in private browsing. */
        }
    }, [navigationWidth]);
    const [query, setQuery] = React.useState('');
    const [announcement, announce] = React.useState('');
    // Re-selecting the same step must recenter after manual panning, even without a hash change.
    const [stepRequest, requestStep] = React.useReducer(
        (value: number) => value + 1,
        0,
    );
    const [stepHover, setStepHover] = React.useState<string | null>(null);
    const aside = React.useRef<HTMLElement>(null);
    const panel = React.useRef<HTMLElement>(null);
    const stepsPanel = React.useRef<HTMLElement>(null);
    const { preference, setPreference } = useGlobalThemePreference();
    const { theme } = useTheme();
    const category = model.categories.find(
        (item) => item.id === view.category,
    )!;
    const doc = selected ? model.docs[model.docOf[selected]] : null;
    const normalizedQuery = query.trim().toLowerCase();
    const results = normalizedQuery
        ? Object.entries(model.nodes)
              .filter(
                  ([id, node]) =>
                      model.docOf[id] &&
                      `${node.label} ${model.docs[model.docOf[id]]?.name ?? ''} ${id}`
                          .toLowerCase()
                          .includes(normalizedQuery),
              )
              .slice(0, 20)
        : [];
    const flowColors = Object.fromEntries(
        Object.entries(model.legend.flows).map(([id, flow]) => [
            `--fa-flow-${id}`,
            theme === 'dark' ? flow.dark_color : flow.color,
        ]),
    ) as React.CSSProperties;
    const activeStep = stepHover ?? stepSelection;
    const resizePanel = (width: number) =>
        setPanelWidth(Math.max(260, Math.min(panelMax, width)));

    const navigate = React.useCallback(
        (viewId: string, nodeId?: string) => {
            window.location.hash = routeHash(viewId, nodeId);
            setRoute(readRoute());
            if (nodeId) {
                setDetailsCollapsed(false);
            }
            if (nodeId && window.innerWidth <= 1150) {
                requestAnimationFrame(() => {
                    panel.current?.scrollIntoView({ block: 'start' });
                    panel.current?.focus({ preventScroll: true });
                });
            }
        },
        [setDetailsCollapsed],
    );

    React.useEffect(() => {
        const changed = () => {
            const route = readRoute();
            setRoute(route);
        };
        window.addEventListener('hashchange', changed);
        return () => window.removeEventListener('hashchange', changed);
    }, []);

    React.useEffect(() => {
        if (selected || stepSelection) {
            setDetailsCollapsed(false);
        }
    }, [view, selected, stepSelection, setDetailsCollapsed]);

    React.useEffect(() => {
        setStepHover(null);
        trackView(view.id);
        document.title = `${view.title} · ${model.site.title}`;
    }, [view]);

    React.useEffect(() => {
        aside.current?.scrollTo(0, 0);
        announce(
            selected
                ? `${nodeLabel(selected)} details opened.`
                : `${view.title} view opened.`,
        );
        if (selected) {
            const canonical = routeHash(view.id, selected);
            if (window.location.hash !== canonical) {
                window.history.replaceState(null, '', canonical);
            }
            trackAction('panel_opened', { item: selected, view: view.id });
        }
    }, [selected, view]);

    React.useEffect(() => {
        const step = view.steps.find((item) => item.id === stepSelection);
        if (step) {
            announce(
                `Step ${step.number} of ${view.steps.length}: ${step.label}.`,
            );
        }
    }, [view, stepSelection, stepRequest]);

    React.useEffect(() => {
        if (detailsCollapsed || window.innerWidth <= 1150) {
            return;
        }
        const frame = requestAnimationFrame(() => {
            const host = aside.current;
            const row = Array.from(
                stepsPanel.current?.querySelectorAll<HTMLElement>(
                    '[data-step-row]',
                ) ?? [],
            )
                .find((item) => item.dataset.stepRow === stepSelection)
                ?.closest('li');
            if (!host || !row) {
                return;
            }
            // Stop a previous smooth scroll before measuring a rapidly reselected step.
            host.scrollTo({ top: host.scrollTop, behavior: 'instant' });
            const bounds = host.getBoundingClientRect();
            const item = row.getBoundingClientRect();
            const top = Math.max(0, bounds.top) + 16;
            const bottom = Math.min(window.innerHeight, bounds.bottom) - 16;
            if (item.top < top || item.bottom > bottom) {
                // scrollIntoView also scrolls the document; walkthrough controls must only move the aside.
                host.scrollBy({
                    top:
                        item.height > bottom - top
                            ? item.top - top
                            : (item.top + item.bottom - top - bottom) / 2,
                    behavior: window.matchMedia(
                        '(prefers-reduced-motion: reduce)',
                    ).matches
                        ? 'instant'
                        : 'smooth',
                });
            }
        });
        return () => cancelAnimationFrame(frame);
    }, [view, stepSelection, stepRequest, detailsCollapsed, headerHeight]);

    const selectStep = (id: string) => {
        const step = view.steps.find((item) => item.id === id);
        if (step) {
            setDetailsCollapsed(false);
            setStepHover(null);
            window.location.hash = stepRouteHash(view.id, step.number);
            setRoute(readRoute());
            requestStep();
        }
    };

    const selectStepFromDiagram = (id: string) => {
        selectStep(id);
        if (window.innerWidth > 1150) {
            return;
        }
        requestAnimationFrame(() => {
            const row = Array.from(
                stepsPanel.current?.querySelectorAll<HTMLButtonElement>(
                    '[data-step-row]',
                ) ?? [],
            ).find((item) => item.dataset.stepRow === id);
            row?.focus({ preventScroll: true });
            row?.closest('li')?.scrollIntoView({ block: 'nearest' });
        });
    };

    return (
        <Flex
            direction="column"
            alignItems="stretch"
            className="architecture-site"
            style={
                {
                    ...flowColors,
                    '--fa-header-height': `${headerHeight}px`,
                    '--fa-panel-width': `${panelWidth}px`,
                    '--fa-nav-width': `${navigationWidth}px`,
                } as React.CSSProperties
            }
            data-navigation-collapsed={navigationCollapsed}
            data-details-collapsed={detailsCollapsed}
            data-resizing={resizing}
            data-theme={theme}
            as={
                <div
                    onKeyDown={(event) => {
                        if (
                            event.key === 'Escape' &&
                            !event.defaultPrevented &&
                            !(event.target instanceof HTMLInputElement)
                        ) {
                            setQuery('');
                            setStepHover(null);
                            navigate(view.id);
                        }
                    }}
                />
            }
        >
            <SkipLink targetId="main" text="Skip to diagram" />
            <Flex
                as="header"
                innerRef={header}
                justify="space-between"
                gap="lg"
                wrap="wrap"
                padding="lg"
                className="fa-header"
            >
                <Flex direction="column" alignItems="stretch" gap="xs">
                    <Title as="h1" size="xl" hasAnchor={false}>
                        {model.site.title}
                    </Title>
                    <Text variant="secondary">
                        Components, connections, and the behaviours they enable
                    </Text>
                </Flex>
                <Flex gap="lg" wrap="wrap">
                    <Link href={model.site.sourceUrl}>
                        Source &amp; Contributing
                    </Link>
                    <Flex gap="sm">
                        <Text size="sm" id="theme-label">
                            Theme
                        </Text>
                        <ToggleButtons<ThemePreference>
                            aria-labelledby="theme-label"
                            size="sm"
                            value={preference}
                            onChange={setPreference}
                            options={[
                                { value: 'system', label: 'System' },
                                { value: 'light', label: 'Light' },
                                { value: 'dark', label: 'Dark' },
                            ]}
                        />
                    </Flex>
                </Flex>
            </Flex>
            <Grid
                columns="var(--fa-columns)"
                gap="none"
                alignItems="start"
                className="fa-shell"
            >
                <Spacing as="nav" aria-label="Diagram views" className="fa-nav">
                    <Flex
                        justify="space-between"
                        gap="xs"
                        marginBottom="sm"
                        className="fa-sidebar-heading"
                    >
                        <Text
                            as={<label htmlFor="search" />}
                            weight="bold"
                            className="fa-sidebar-label"
                        >
                            Find a Component
                        </Text>
                        <Button
                            className="fa-collapse-control"
                            icon={
                                navigationCollapsed
                                    ? PanelLeftGrowIcon
                                    : PanelLeftShrinkIcon
                            }
                            ariaLabel={
                                navigationCollapsed
                                    ? 'Expand navigation'
                                    : 'Collapse navigation'
                            }
                            ariaAttrs={{
                                'aria-expanded': !navigationCollapsed,
                                'aria-controls': 'navigation',
                            }}
                            title={
                                navigationCollapsed
                                    ? 'Expand navigation'
                                    : 'Collapse navigation'
                            }
                            size="sm"
                            isBorderless
                            onClick={() =>
                                setNavigationCollapsed(
                                    (collapsed) => !collapsed,
                                )
                            }
                        />
                    </Flex>
                    <div id="navigation">
                        <Flex
                            direction="column"
                            alignItems="stretch"
                            gap="sm"
                            marginBottom="lg"
                        >
                            <InputSearch
                                id="search"
                                isFullWidth
                                autoComplete="off"
                                value={query}
                                placeholder="Search components"
                                onChange={(event) =>
                                    setQuery(event.target.value)
                                }
                            />
                            {normalizedQuery && (
                                <Flex
                                    as="ul"
                                    direction="column"
                                    alignItems="stretch"
                                    gap="sm"
                                    className="fa-results"
                                    aria-label="Matching components"
                                >
                                    {results.map(([id]) => {
                                        const target = view.nodeIds.includes(id)
                                            ? view
                                            : model.views.find((item) =>
                                                  item.nodeIds.includes(id),
                                              );
                                        return (
                                            target && (
                                                <Text as="li" key={id}>
                                                    <Link
                                                        href={routeHash(
                                                            target.id,
                                                            id,
                                                        )}
                                                        onClick={(event) => {
                                                            event.preventDefault();
                                                            navigate(
                                                                target.id,
                                                                id,
                                                            );
                                                            setQuery('');
                                                        }}
                                                    >
                                                        {nodeLabel(id)}
                                                    </Link>
                                                </Text>
                                            )
                                        );
                                    })}
                                    {!results.length && (
                                        <Text as="li" variant="secondary">
                                            No matching components.
                                        </Text>
                                    )}
                                </Flex>
                            )}
                        </Flex>
                        <ToggleButtons<Category>
                            aria-label="Diagram category"
                            isFullWidth
                            size="sm"
                            value={view.category}
                            onChange={(next) => {
                                const target = model.views.find(
                                    (item) => item.category === next,
                                );
                                if (target) {
                                    navigate(target.id);
                                }
                            }}
                            options={[
                                {
                                    value: 'architecture',
                                    label: 'Architecture',
                                },
                                { value: 'flow', label: 'Flows' },
                            ]}
                        />
                        <Spacing
                            as="div"
                            marginTop="lg"
                            className="fa-desktop-nav"
                        >
                            <VerticalNav
                                isFullWidth
                                items={category.groups.map((group) => ({
                                    sectionLabel: group,
                                    items: model.views
                                        .filter(
                                            (item) =>
                                                item.category ===
                                                    view.category &&
                                                item.group === group,
                                        )
                                        .map((item) => ({
                                            key: item.id,
                                            label: item.title,
                                            href: routeHash(item.id),
                                            isActive: item.id === view.id,
                                            ariaAttrs: {
                                                'aria-current':
                                                    item.id === view.id
                                                        ? ('page' as const)
                                                        : undefined,
                                            },
                                            dataAttrs: { 'data-view': item.id },
                                        })),
                                }))}
                            />
                            <Text
                                as="p"
                                size="sm"
                                variant="secondary"
                                marginTop="lg"
                            >
                                {view.category === 'flow'
                                    ? 'One triggered behaviour, followed step by step. Check the evidence and limitations.'
                                    : 'Maps of components and dependencies. Select a component to explore its role and sources.'}
                            </Text>
                        </Spacing>
                        <Spacing
                            as="div"
                            marginTop="md"
                            className="fa-mobile-nav"
                        >
                            <Select
                                aria-label="Diagram view"
                                isFullWidth
                                clearable={false}
                                searchable
                                value={view.id}
                                options={model.views
                                    .filter(
                                        (item) =>
                                            item.category === view.category,
                                    )
                                    .map((item) => ({
                                        value: item.id,
                                        label: `${item.group}: ${item.title}`,
                                    }))}
                                onChange={(option) => navigate(option.value)}
                            />
                        </Spacing>
                    </div>
                </Spacing>
                <SidebarResizer
                    side="navigation"
                    width={navigationWidth}
                    min={224}
                    max={navigationMax}
                    defaultWidth={224}
                    onResize={(width) =>
                        setNavigationWidth(
                            Math.max(224, Math.min(navigationMax, width)),
                        )
                    }
                    onResizing={setResizing}
                />
                <Flex
                    as={<main tabIndex={-1} />}
                    id="main"
                    direction="column"
                    alignItems="stretch"
                    gap="lg"
                    padding="lg"
                    className="fa-main"
                >
                    <Flex direction="column" alignItems="stretch" gap="sm">
                        <Text variant="secondary" size="sm">
                            {category.title} / {view.group}
                        </Text>
                        <Title as="h2" size="xxl" hasAnchor={false}>
                            {view.title}
                        </Title>
                        <Text variant="secondary">
                            {
                                view.nodeIds.filter(
                                    (id) => !model.nodes[id].isFrame,
                                ).length
                            }{' '}
                            components ·{' '}
                            {view.category === 'flow'
                                ? `${view.steps.length} ordered steps`
                                : `${view.edges.length} connections`}
                        </Text>
                        <Text>
                            {view.category === 'flow'
                                ? 'Follow the numbered arrows. Select a step to see its evidence.'
                                : 'Select a component for details. Colours group connections; frames show where things run.'}
                        </Text>
                    </Flex>
                    <Diagram
                        key={view.id}
                        view={view}
                        selected={selected}
                        onSelect={(id) =>
                            navigate(
                                view.id,
                                id ??
                                    (detailsCollapsed &&
                                    window.innerWidth > 1150
                                        ? (selected ?? undefined)
                                        : undefined),
                            )
                        }
                        activeStep={activeStep}
                        selectedStep={stepSelection}
                        stepRequest={stepRequest}
                        onStepHover={setStepHover}
                        onStepSelect={selectStep}
                        onStepInspect={selectStepFromDiagram}
                    />
                    <Text as="footer" size="sm" variant="secondary">
                        Source-backed reference, not a live status page.
                        Configuration evidence does not establish runtime
                        success.
                    </Text>
                </Flex>
                <SidebarResizer
                    side="details"
                    width={panelWidth}
                    min={260}
                    max={panelMax}
                    defaultWidth={372}
                    onResize={resizePanel}
                    onResizing={setResizing}
                />
                <Flex
                    as={<aside aria-label="View guide and component details" />}
                    innerRef={aside}
                    direction="column"
                    alignItems="stretch"
                    gap="lg"
                    className="fa-aside"
                >
                    <Flex
                        justify="space-between"
                        gap="sm"
                        className="fa-sidebar-heading"
                    >
                        <Text
                            variant="secondary"
                            size="sm"
                            className="fa-sidebar-label"
                        >
                            {doc
                                ? selected && model.nodes[selected].isFrame
                                    ? 'Where It Runs'
                                    : 'Component'
                                : 'View Guide'}
                        </Text>
                        <Button
                            className="fa-collapse-control"
                            icon={
                                detailsCollapsed
                                    ? PanelRightGrowIcon
                                    : PanelRightShrinkIcon
                            }
                            ariaLabel={
                                detailsCollapsed
                                    ? 'Expand details'
                                    : 'Collapse details'
                            }
                            ariaAttrs={{
                                'aria-expanded': !detailsCollapsed,
                                'aria-controls': 'details-content',
                            }}
                            title={
                                detailsCollapsed
                                    ? 'Expand details'
                                    : 'Collapse details'
                            }
                            size="sm"
                            isBorderless
                            onClick={() =>
                                setDetailsCollapsed((collapsed) => !collapsed)
                            }
                        />
                        {doc && (
                            <Button
                                className="fa-details-guide"
                                label="View Guide"
                                size="sm"
                                isBorderless
                                onClick={() => navigate(view.id)}
                            />
                        )}
                    </Flex>
                    <Flex
                        id="details-content"
                        direction="column"
                        alignItems="stretch"
                        gap="lg"
                    >
                        <Flex
                            as={
                                <section
                                    tabIndex={-1}
                                    aria-label={
                                        doc
                                            ? `${doc.name} details`
                                            : 'View guide'
                                    }
                                />
                            }
                            innerRef={panel}
                            id="details"
                            direction="column"
                            alignItems="stretch"
                            gap="md"
                            className="fa-details"
                        >
                            <Title as="h3" size="xl" hasAnchor={false}>
                                {doc?.name ?? view.title}
                            </Title>
                            {(doc || view.category === 'architecture') && (
                                <Prose
                                    html={
                                        doc?.descriptionHtml ?? view.introHtml
                                    }
                                />
                            )}
                            <LinkChips links={doc?.links ?? view.links} />
                            {selected && (
                                <Flex
                                    direction="column"
                                    alignItems="stretch"
                                    gap="sm"
                                >
                                    <Title as="h4" size="md" hasAnchor={false}>
                                        Also On
                                    </Title>
                                    {model.views
                                        .filter(
                                            (item) =>
                                                item.id !== view.id &&
                                                item.id !== 'complete' &&
                                                item.nodeIds.includes(selected),
                                        )
                                        .map((item) => (
                                            <Link
                                                key={item.id}
                                                href={routeHash(
                                                    item.id,
                                                    selected,
                                                )}
                                            >
                                                {item.title}
                                            </Link>
                                        ))}
                                </Flex>
                            )}
                            {!selected && view.relatedFlows.length > 0 && (
                                <Flex
                                    direction="column"
                                    alignItems="stretch"
                                    gap="sm"
                                >
                                    <Title as="h4" size="md" hasAnchor={false}>
                                        Related Flows
                                    </Title>
                                    {view.relatedFlows.map((id) => (
                                        <Link key={id} href={routeHash(id)}>
                                            {
                                                model.views.find(
                                                    (item) => item.id === id,
                                                )?.title
                                            }
                                        </Link>
                                    ))}
                                </Flex>
                            )}
                            <Sources
                                key={selected ?? view.id}
                                sources={doc ? doc.sources : view.sources}
                            />
                        </Flex>
                        {view.scenario && (
                            <Flex
                                as={
                                    <section aria-label="Flow scenario and ordered steps" />
                                }
                                innerRef={stepsPanel}
                                direction="column"
                                alignItems="stretch"
                                gap="lg"
                                className="fa-flow-panel"
                            >
                                <Flex
                                    direction="column"
                                    alignItems="stretch"
                                    gap="md"
                                    className="fa-scenario"
                                >
                                    <Flex
                                        justify="space-between"
                                        gap="sm"
                                        wrap="wrap"
                                    >
                                        <Title
                                            as="h3"
                                            size="lg"
                                            hasAnchor={false}
                                        >
                                            Scenario
                                        </Title>
                                        <Button
                                            label="Read Steps"
                                            size="sm"
                                            onClick={() =>
                                                selectStepFromDiagram(
                                                    view.steps[0].id,
                                                )
                                            }
                                        />
                                    </Flex>
                                    <dl>
                                        <dt>Trigger</dt>
                                        <dd>{view.scenario.trigger}</dd>
                                        <dt>Actor</dt>
                                        <dd>{view.scenario.actor}</dd>
                                        <dt>Preconditions</dt>
                                        <dd>
                                            {view.scenario.preconditions
                                                .length ? (
                                                <ul>
                                                    {view.scenario.preconditions.map(
                                                        (text) => (
                                                            <li key={text}>
                                                                {text}
                                                            </li>
                                                        ),
                                                    )}
                                                </ul>
                                            ) : (
                                                'None specified.'
                                            )}
                                        </dd>
                                        <dt>End State</dt>
                                        <dd>{view.scenario.endState}</dd>
                                        <dt>Limitations</dt>
                                        <dd>
                                            {view.scenario.limitations
                                                .length ? (
                                                <ul>
                                                    {view.scenario.limitations.map(
                                                        (text) => (
                                                            <li key={text}>
                                                                {text}
                                                            </li>
                                                        ),
                                                    )}
                                                </ul>
                                            ) : (
                                                'None specified.'
                                            )}
                                        </dd>
                                    </dl>
                                    <Link
                                        href={routeHash(
                                            view.scenario.architectureView,
                                        )}
                                    >
                                        Architecture:{' '}
                                        {
                                            model.views.find(
                                                (item) =>
                                                    item.id ===
                                                    view.scenario
                                                        ?.architectureView,
                                            )?.title
                                        }
                                    </Link>
                                </Flex>
                                <Title as="h3" size="lg" hasAnchor={false}>
                                    Ordered Steps
                                </Title>
                                <ol className="fa-steps">
                                    {view.steps.map((step) => (
                                        <li
                                            key={step.id}
                                            className={
                                                activeStep === step.id
                                                    ? 'is-active'
                                                    : ''
                                            }
                                            onMouseEnter={() =>
                                                setStepHover(step.id)
                                            }
                                            onMouseLeave={() =>
                                                setStepHover(null)
                                            }
                                        >
                                            <Action
                                                className="fa-step-button"
                                                dataAttrs={{
                                                    'data-step-row': step.id,
                                                }}
                                                ariaAttrs={{
                                                    'aria-pressed':
                                                        stepSelection ===
                                                        step.id,
                                                }}
                                                onFocus={() =>
                                                    setStepHover(step.id)
                                                }
                                                onBlur={() =>
                                                    setStepHover(null)
                                                }
                                                onClick={() =>
                                                    selectStep(step.id)
                                                }
                                            >
                                                <span>
                                                    <span className="fa-step-number">
                                                        {step.number}
                                                    </span>
                                                    <span>{step.label}</span>
                                                </span>
                                            </Action>
                                            <Text
                                                as="p"
                                                size="sm"
                                                variant="secondary"
                                            >
                                                {nodeLabel(step.from)} →{' '}
                                                {nodeLabel(step.to)}
                                            </Text>
                                            <Text
                                                as="p"
                                                size="sm"
                                                className={`fa-verification fa-verification--${step.verification}`}
                                            >
                                                {step.verification === 'code'
                                                    ? 'Code Evidence'
                                                    : step.verification ===
                                                        'configuration'
                                                      ? 'Configuration Evidence'
                                                      : 'Unverified / Outside Repository'}
                                            </Text>
                                            {step.note && (
                                                <Text as="p" size="sm">
                                                    {step.note}
                                                </Text>
                                            )}
                                            <Flex
                                                direction="column"
                                                alignItems="stretch"
                                                gap="xs"
                                                className="fa-sources"
                                            >
                                                {step.sources.map((source) => (
                                                    <Link
                                                        key={`${source.path}:${source.symbol}:${source.lines?.join('-')}`}
                                                        href={source.url}
                                                        size="sm"
                                                    >
                                                        {source.path}
                                                        {source.lines
                                                            ? `:${source.lines.join('–')}`
                                                            : ''}
                                                        {source.symbol
                                                            ? ` · ${source.symbol}`
                                                            : ''}
                                                    </Link>
                                                ))}
                                            </Flex>
                                        </li>
                                    ))}
                                </ol>
                                <Accordion title="View Guide" size="md">
                                    <Prose html={view.introHtml} />
                                </Accordion>
                            </Flex>
                        )}
                    </Flex>
                </Flex>
            </Grid>
            <VisuallyHidden role="status" aria-live="polite">
                {announcement}
            </VisuallyHidden>
        </Flex>
    );
}
