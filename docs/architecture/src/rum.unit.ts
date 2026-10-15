describe('optional architecture RUM', () => {
    const originalLocation = window.location;
    const config = {
        applicationId: 'test',
        clientToken: 'public-test',
        service: 'architecture-site',
        site: 'datadoghq.com',
        env: 'test',
    };
    const sdk = {
        getInitConfiguration: jest.fn(),
        init: jest.fn(),
        startView: jest.fn(),
        addAction: jest.fn(),
    };

    beforeEach(() => {
        jest.resetModules();
        jest.resetAllMocks();
        document.head.innerHTML = '';
        Object.defineProperty(window, 'location', {
            configurable: true,
            value: new URL('https://architecture-site.us1.ddbuild.io/'),
        });
        jest.doMock('@monitoring-lib/rum-static-apps', () => ({
            datadogRum: sdk,
        }));
        jest.doMock('./model', () => ({ model: { site: { rum: config } } }));
    });

    afterEach(() => {
        Object.defineProperty(window, 'location', { value: originalLocation });
        jest.dontMock('@monitoring-lib/rum-static-apps');
        jest.dontMock('./model');
    });

    it.each([undefined, null])(
        'does not enable RUM with site.rum = %s',
        async (rum) => {
            jest.doMock('./model', () => ({ model: { site: { rum } } }));
            const { trackView, trackAction } = await import('./rum');
            trackView('overview');
            trackAction('panel_opened', { item: 'database', view: 'overview' });
            expect(sdk.getInitConfiguration).not.toHaveBeenCalled();
            expect(sdk.init).not.toHaveBeenCalled();
            expect(sdk.startView).not.toHaveBeenCalled();
            expect(sdk.addAction).not.toHaveBeenCalled();
            expect(document.head.querySelector('script')).toBeNull();
        },
    );

    it('initializes the shared SDK once with site.rum and preserves view and action order', async () => {
        const { trackView, trackAction } = await import('./rum');
        trackView('overview');
        trackAction('panel_opened', { item: 'database', view: 'overview' });
        trackAction('flow_toggled', {
            flow: 'data',
            shown: false,
            view: 'overview',
        });
        expect(sdk.init).toHaveBeenCalledTimes(1);
        expect(sdk.init).toHaveBeenCalledWith({
            ...config,
            version: undefined,
            sessionSampleRate: 100,
            sessionReplaySampleRate: 0,
            trackViewsManually: true,
            trackUserInteractions: true,
            trackResources: true,
            trackLongTasks: true,
            defaultPrivacyLevel: 'mask-user-input',
        });
        expect(sdk.startView).toHaveBeenCalledTimes(1);
        expect(sdk.startView).toHaveBeenCalledWith({ name: 'overview' });
        expect(sdk.addAction.mock.calls).toEqual([
            ['panel_opened', { item: 'database', view: 'overview' }],
            ['flow_toggled', { flow: 'data', shown: false, view: 'overview' }],
        ]);
        expect(sdk.init.mock.invocationCallOrder[0]).toBeLessThan(
            sdk.startView.mock.invocationCallOrder[0],
        );
        expect(sdk.startView.mock.invocationCallOrder[0]).toBeLessThan(
            sdk.addAction.mock.invocationCallOrder[0],
        );
        expect(document.head.querySelector('script')).toBeNull();
    });

    it('starts a view only when the diagram view id changes, including return visits', async () => {
        const { trackView, trackAction } = await import('./rum');
        trackView('overview');
        trackView('overview');
        trackAction('panel_opened', { item: 'database', view: 'overview' });
        trackView('overview');
        trackView('flow-request');
        trackView('flow-request');
        trackView('overview');
        expect(sdk.startView.mock.calls).toEqual([
            [{ name: 'overview' }],
            [{ name: 'flow-request' }],
            [{ name: 'overview' }],
        ]);
        expect(sdk.init).toHaveBeenCalledTimes(1);
    });

    it('does not reinitialize an already initialized shared SDK', async () => {
        sdk.getInitConfiguration.mockReturnValue(config);
        const { trackView, trackAction } = await import('./rum');
        trackView('overview');
        trackAction('panel_opened', { item: 'database', view: 'overview' });
        expect(sdk.init).not.toHaveBeenCalled();
        expect(sdk.startView).toHaveBeenCalledWith({ name: 'overview' });
        expect(sdk.addAction).toHaveBeenCalledWith('panel_opened', {
            item: 'database',
            view: 'overview',
        });
    });

    it.each([
        'file:///tmp/architecture-site/index.html',
        'https://localhost:8443/',
        'http://localhost./',
        'https://preview.localhost/',
        'http://127.0.0.1:8787/',
        'http://127.1.2.3/',
        'http://[::1]:8787/',
        'http://0.0.0.0:8787/',
    ])(
        'suppresses RUM on %s even with site.rum and an initialized SDK',
        async (url) => {
            Object.defineProperty(window, 'location', { value: new URL(url) });
            sdk.getInitConfiguration.mockReturnValue(config);
            const { trackView, trackAction } = await import('./rum');
            trackView('overview');
            trackAction('panel_opened', { item: 'database', view: 'overview' });
            trackAction('flow_toggled', {
                flow: 'data',
                shown: true,
                view: 'overview',
            });
            expect(sdk.getInitConfiguration).not.toHaveBeenCalled();
            expect(sdk.init).not.toHaveBeenCalled();
            expect(sdk.startView).not.toHaveBeenCalled();
            expect(sdk.addAction).not.toHaveBeenCalled();
        },
    );

    it('tolerates initialization failure without retrying or sending events', async () => {
        sdk.init.mockImplementation(() => {
            throw new Error('SDK unavailable');
        });
        const { trackView, trackAction } = await import('./rum');
        expect(() => {
            trackView('overview');
            trackAction('panel_opened', { item: 'database', view: 'overview' });
            trackView('flow-request');
        }).not.toThrow();
        expect(sdk.init).toHaveBeenCalledTimes(1);
        expect(sdk.startView).not.toHaveBeenCalled();
        expect(sdk.addAction).not.toHaveBeenCalled();
    });
});
