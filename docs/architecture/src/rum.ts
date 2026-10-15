import { datadogRum } from '@monitoring-lib/rum-static-apps';

import { model } from './model';

// Set by the static-app build in index.html.
declare const STATIC_APP_VERSION: string | undefined;

let sdk: typeof datadogRum | null | undefined;
let currentView: string | undefined;

function getRum(): typeof datadogRum | null {
    if (sdk !== undefined) {
        return sdk;
    }
    sdk = null;
    const { protocol, hostname } = window.location;
    const host = hostname.toLowerCase().replace(/\.$/, '');
    if (
        !model.site.rum ||
        protocol === 'file:' ||
        host === 'localhost' ||
        host.endsWith('.localhost') ||
        /^127\./.test(host) ||
        host === '[::1]' ||
        host === '::1' ||
        host === '0.0.0.0'
    ) {
        return null;
    }
    try {
        if (!datadogRum.getInitConfiguration()) {
            datadogRum.init({
                ...model.site.rum,
                version:
                    typeof STATIC_APP_VERSION === 'string'
                        ? STATIC_APP_VERSION
                        : undefined,
                sessionSampleRate: 100,
                sessionReplaySampleRate: 0,
                trackViewsManually: true,
                trackUserInteractions: true,
                trackResources: true,
                trackLongTasks: true,
                defaultPrivacyLevel: 'mask-user-input',
            });
        }
        sdk = datadogRum;
    } catch {
        // Optional telemetry must not prevent using the reference.
    }
    return sdk;
}

export function trackView(name: string): void {
    const rum = getRum();
    if (rum && name !== currentView) {
        rum.startView({ name });
        currentView = name;
    }
}

export function trackAction(
    name: 'panel_opened' | 'flow_toggled',
    context: Record<string, unknown>,
): void {
    getRum()?.addAction(name, context);
}
