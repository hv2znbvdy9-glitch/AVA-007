import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import {test} from 'tap';

import Api from '../lib/api.js';
import {normalizeGlobs} from '../lib/globs.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

function createApi(projectDir) {
	const extensions = ['cjs'];
	return new Api({
		cacheEnabled: false,
		chalkOptions: {level: 0},
		concurrency: 2,
		experiments: {},
		extensions,
		globs: normalizeGlobs({extensions, providers: []}),
		match: [],
		nodeArguments: process.execArgv,
		projectDir,
	});
}

test('glob setup errors are not masked by selection insights', async t => {
	// A regular file cannot be used as a glob cwd. This forces findTests() to
	// fail before it can assign the discovered test-file list.
	const invalidProjectDir = path.join(__dirname, 'api-glob-errors.js');
	const api = createApi(invalidProjectDir);
	const internalErrors = [];

	api.on('run', plan => {
		plan.status.on('stateChange', event => {
			if (event.type === 'internal-error') {
				internalErrors.push(event.err);
			}
		});
	});

	const runStatus = await api.run();

	t.equal(runStatus.selectionInsights.testFileCount, 0);
	t.equal(internalErrors.length, 1);
	t.notMatch(internalErrors[0].message, /testFiles|undefined/i);
});
