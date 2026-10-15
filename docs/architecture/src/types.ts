export type Category = 'architecture' | 'flow';
export type ThemePreference = 'system' | 'light' | 'dark';
export type Links = Partial<
    Record<
        | 'code'
        | 'wiki'
        | 'k8s_chart'
        | 'datadog_service'
        | 'logs'
        | 'dashboard',
        string
    >
>;
export type Citation = {
    text: string;
    href: string | null;
    detail: string | null;
};
export type Source = {
    path: string;
    symbol: string;
    lines?: [number, number];
    url: string;
};
export type Edge = {
    id: string;
    from: string;
    to: string;
    label: string;
    flow: string;
    kind: 'call' | 'read' | 'traffic';
};
export type Step = Edge & {
    number: number;
    edgeId: string;
    verification: 'code' | 'configuration' | 'unverified';
    sources: Source[];
    note?: string;
};
export type ArchitectureView = {
    id: string;
    title: string;
    category: Category;
    group: string;
    introHtml: string;
    links: Links;
    sources?: Citation[];
    nodeIds: string[];
    flowIds: string[];
    edges: Edge[];
    relatedFlows: string[];
    scenario: null | {
        actor: string;
        trigger: string;
        preconditions: string[];
        endState: string;
        limitations: string[];
        architectureView: string;
    };
    steps: Step[];
};
export type Data = {
    schemaVersion: 1;
    site: {
        title: string;
        sourceUrl: string;
        theme: { default: ThemePreference };
        rum?: null | {
            applicationId: string;
            clientToken: string;
            service: string;
            site: string;
            env: string;
        };
    };
    categories: Array<{ id: Category; title: string; groups: string[] }>;
    nodes: Record<
        string,
        {
            label: string;
            shape:
                | 'service'
                | 'external'
                | 'store'
                | 'object'
                | 'workload'
                | null;
            isFrame: boolean;
        }
    >;
    docOf: Record<string, string>;
    docs: Record<
        string,
        {
            name: string;
            descriptionHtml: string;
            links: Links;
            sources?: Citation[];
        }
    >;
    views: ArchitectureView[];
    legend: {
        flows: Record<
            string,
            { label: string; color: string; dark_color: string }
        >;
        kinds: Record<string, { label: string }>;
        shapes: Record<string, { label: string }>;
        frames: Record<string, { label: string }>;
    };
    diagrams: Record<string, string>;
};
