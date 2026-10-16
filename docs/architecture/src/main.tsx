import '@lib/polyfills';
import { DruidsEnvironment } from '@druids/ui/layout/DruidsEnvironment';
import { SavedThemes } from '@druids/ui/lib/color/theme';
import { ErrorBoundary } from '@druids/ui/misc/ErrorBoundary';
import { addDivAsFirstChild } from '@lib/dom';
import { createRoot } from 'react-dom/client';
import * as React from 'react';

import { App } from './App';
import { model } from './model';
import './architecture.less';

createRoot(addDivAsFirstChild('architecture-site-root')).render(
    <DruidsEnvironment
        fallbackThemePreference={SavedThemes[model.site.theme.default]}
        backgroundColor="secondary"
    >
        <ErrorBoundary>
            <App />
        </ErrorBoundary>
    </DruidsEnvironment>,
);
