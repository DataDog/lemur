import { model, nodeLabel, readRoute, routeHash, stepRouteHash } from './model';

describe('architecture hash routing', () => {
    const defaultView =
        model.views.find((view) => view.id === 'overview') ?? model.views[0];
    const architecture = model.views.find(
        (view) => view.category === 'architecture',
    )!;
    it("defaults to the site's starting view for empty, unknown, and malformed hashes", () => {
        for (const hash of ['', '#unknown', '#%E0%A4%A']) {
            expect(readRoute(hash).view).toBe(defaultView);
            expect(readRoute(hash).selected).toBeNull();
        }
    });

    it('retains every existing view hash and derives its category', () => {
        for (const view of model.views) {
            expect(readRoute(routeHash(view.id)).view).toBe(view);
        }
    });

    it('round-trips documented nodes, including original D2 scoped hashes', () => {
        for (const view of model.views) {
            for (const id of view.nodeIds.filter((node) => model.docOf[node])) {
                expect(readRoute(routeHash(view.id, id)).selected).toBe(id);
                expect(
                    readRoute(`#${view.id}/region.zone.group.${id}`).selected,
                ).toBe(id);
            }
        }
    });

    it('opens flows at step 1 and round-trips every numbered step', () => {
        for (const view of model.views) {
            expect(readRoute(routeHash(view.id)).step).toBe(
                view.steps[0]?.id ?? null,
            );
            for (const step of view.steps) {
                const route = readRoute(stepRouteHash(view.id, step.number));
                expect(route.view).toBe(view);
                expect(route.step).toBe(step.id);
                expect(route.selected).toBeNull();
            }
        }
    });

    it('falls back to step 1 for invalid flow steps without opening node details', () => {
        const view = model.views.find((item) => item.category === 'flow')!;
        for (const suffix of [
            'step-0',
            'step--1',
            'step-999',
            'step-1.5',
            'step-01',
            'step-x',
            'step-1/extra',
        ]) {
            const route = readRoute(`#${view.id}/${suffix}`);
            expect(route.view).toBe(view);
            expect(route.step).toBe(view.steps[0].id);
            expect(route.selected).toBeNull();
        }
    });

    it('decodes step links and keeps architecture routes unnumbered', () => {
        const view = model.views.find((item) => item.category === 'flow')!;
        expect(readRoute(`#${view.id}/%73tep-2`).step).toBe(view.steps[1].id);
        expect(readRoute(routeHash(architecture.id, 'step-1')).step).toBeNull();
        expect(
            readRoute(routeHash(architecture.id, 'step-1')).selected,
        ).toBeNull();
        expect(readRoute('#unknown/step-1').step).toBe(
            defaultView.steps[0]?.id ?? null,
        );
        expect(readRoute(`#${view.id}/%E0%A4%A`).step).toBe(
            defaultView.steps[0]?.id ?? null,
        );
    });

    it('retains component routes within flows', () => {
        for (const view of model.views.filter(
            (item) => item.category === 'flow',
        )) {
            const node = view.nodeIds.find((id) => model.docOf[id])!;
            const route = readRoute(routeHash(view.id, node));
            expect(route.selected).toBe(node);
            expect(route.step).toBe(view.steps[0].id);
        }
    });

    it('does not open details for unknown nodes', () => {
        expect(
            readRoute(routeHash(architecture.id, 'not-a-node')).selected,
        ).toBeNull();
    });

    it('does not open a component outside the current view', () => {
        for (const view of model.views) {
            for (const missing of Object.keys(model.nodes).filter(
                (id) => !view.nodeIds.includes(id),
            )) {
                expect(
                    readRoute(routeHash(view.id, missing)).selected,
                ).toBeNull();
            }
        }
    });

    it('escapes hash segments and flattens multiline display labels', () => {
        expect(routeHash('a b', 'c/d')).toBe('#a%20b/c%2Fd');
        for (const id of Object.keys(model.nodes)) {
            expect(nodeLabel(id)).not.toContain('\n');
        }
    });
});
