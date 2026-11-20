import data from './architecture-data.json';
import type { Data, ArchitectureView } from './types';

// Matches the generator's reserved badge space.
export const FA_STEP_COUNTER_MAX = 2;

export const model = data as Data;
if (model.schemaVersion !== 1 || !model.views.length) {
    throw new Error(
        'Unsupported architecture data. Regenerate with generate-diagram.py.',
    );
}

export function routeHash(viewId: string, nodeId?: string): string {
    return `#${encodeURIComponent(viewId)}${nodeId ? `/${encodeURIComponent(nodeId)}` : ''}`;
}

export function stepRouteHash(viewId: string, number: number): string {
    return routeHash(viewId, `step-${number}`);
}

export function readRoute(hash: string = window.location.hash): {
    view: ArchitectureView;
    selected: string | null;
    step: string | null;
} {
    let parts: string[];
    try {
        parts = hash.replace(/^#/, '').split('/').map(decodeURIComponent);
    } catch {
        parts = [];
    }
    const view =
        model.views.find((item) => item.id === parts[0]) ??
        model.views.find((item) => item.id === 'overview') ??
        model.views[0];
    const requested = parts.slice(1).join('/');
    // The original page linked D2's scoped paths; model IDs are their final segment.
    const selected =
        view.nodeIds.find((id) => id === requested) ??
        view.nodeIds.find((id) => id === requested.split('.').pop()) ??
        null;
    return {
        view,
        selected: selected && model.docOf[selected] ? selected : null,
        step:
            view.steps.find((item) => requested === `step-${item.number}`)
                ?.id ??
            view.steps[0]?.id ??
            null,
    };
}

export function nodeLabel(id: string): string {
    return model.nodes[id]?.label.replace(/\n/g, ' · ') ?? id;
}
