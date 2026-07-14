const http = require('node:http');
const fs = require('node:fs');
const {test, expect} = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const graph = {
  metadata: {hostname: 'synthetic-browser-fixture', generated_at: '2026-07-11T00:00:00Z'},
  graph: {
    nodes: [
      {id: 'app', kind: 'rs_Application', label: 'Demo App', x: 200, y: 180, properties: {bundle_id: 'com.example.demo', _color: '#0a61c9'}},
      {id: 'fda', kind: 'rs_TCCPermission', label: 'Full Disk Access', x: 420, y: 180, properties: {_color: '#bd2432'}},
    ],
    edges: [{source: 'app', target: 'fda', kind: 'rs_HAS_TCC_GRANT', properties: {_traversable: true}}],
  },
};

function assembledViewer(live) {
  let script = [
    fs.readFileSync('graph/viewer.js', 'utf8'),
    fs.readFileSync('graph/viewer_spatial.js', 'utf8'),
    fs.readFileSync('graph/viewer_render.js', 'utf8'),
    fs.readFileSync('graph/viewer_analysis.js', 'utf8'),
    fs.readFileSync('graph/viewer_controls.js', 'utf8'),
    fs.readFileSync('graph/viewer_live.js', 'utf8'),
    fs.readFileSync('graph/viewer_shell.js', 'utf8'),
  ].join('\n');
  const payload = live ? {metadata: {}, graph: {nodes: [], edges: []}} : graph;
  script = script.replace(
    'let DATA = null /* VIEWER_DATA */;',
    `${live ? "const __ROOTSTOCK_LIVE__ = true; const API_BASE = '';" : ''}\nlet DATA = ${JSON.stringify(payload)};`,
  );
  return fs.readFileSync('graph/viewer_template.html', 'utf8')
    .replace('{{VIEWER_TITLE}}', live ? 'Live fixture' : 'Static fixture')
    .replace('{{VIEWER_CSS}}', fs.readFileSync('graph/viewer.css', 'utf8'))
    .replace('{{VIEWER_JS}}', script);
}

let server;
let origin;

const apiPayloads = new Map([
  ['/api/queries', [
    {id: '01', name: 'Fixture query', purpose: 'Browser result fixture', category: 'Blue Team', severity: 'Informational'},
  ]],
  ['/api/queries/01/run', {rows: [{name: 'Demo App'}], count: 1}],
  ['/api/owned', {owned: [], count: 0}],
]);

function isViewerPage(url) {
  return url === '/static' || url === '/live';
}

function hasFixtureToken(request) {
  return request.headers.authorization === 'Bearer browser-fixture-token';
}

function serveFixtureApi(request, response) {
  response.setHeader('Content-Type', 'application/json');
  if (request.url === '/api/graph') {
    return response.end(JSON.stringify(graph));
  }
  const payload = apiPayloads.get(request.url);
  if (payload) return response.end(JSON.stringify(payload));
  response.writeHead(404);
  return response.end(JSON.stringify({detail: 'Not found'}));
}

function handleFixtureRequest(request, response) {
  if (isViewerPage(request.url)) {
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    return response.end(assembledViewer(request.url === '/live'));
  }
  if (!hasFixtureToken(request)) {
    response.writeHead(401, {'Content-Type': 'application/json'});
    return response.end(JSON.stringify({detail: 'Missing or invalid bearer token'}));
  }
  return serveFixtureApi(request, response);
}

test.beforeAll(async () => {
  server = http.createServer(handleFixtureRequest);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  await new Promise(resolve => server.close(resolve));
});

async function expectNoSeriousAxeFindings(page) {
  const result = await new AxeBuilder({page}).analyze();
  expect(result.violations.filter(item => ['serious', 'critical'].includes(item.impact))).toEqual([]);
}

test('static graph supports keyboard selection, path building, and theme override', async ({page}) => {
  await page.goto(`${origin}/static`);
  await expect(page.getByRole('button', {name: /Demo App/})).toBeVisible();
  await page.getByRole('button', {name: /Demo App/}).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', {name: 'Demo App'})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
  await page.getByRole('button', {name: 'Build path'}).click();
  await page.getByRole('button', {name: /Demo App/}).click();
  await page.getByRole('button', {name: /Full Disk Access/}).click();
  await expect(page.getByText('1 hop', {exact: true})).toBeVisible();
  await page.getByLabel('Theme').selectOption('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expectNoSeriousAxeFindings(page);
});

test('live viewer uses an inline session-only token gate', async ({page}) => {
  await page.goto(`${origin}/live`);
  await expect(page.getByRole('heading', {name: 'Connect to this Rootstock session'})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
  await page.getByLabel('API token').fill('browser-fixture-token');
  await page.getByRole('button', {name: 'Connect'}).click();
  await expect(page.getByText('Live · connected')).toBeVisible();
  await expect(page.getByRole('button', {name: /Demo App/})).toBeVisible();
  await page.getByRole('tab', {name: 'Queries'}).click();
  await page.getByRole('button', {name: /Fixture query/}).click();
  await expect(page.getByRole('heading', {name: /Fixture query/})).toBeVisible();
  await expect(page.getByRole('button', {name: 'Highlight node'})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
});

test('live refresh clears interaction state from the graph it replaces', async ({page}) => {
  await page.goto(`${origin}/live`);
  await page.getByLabel('API token').fill('browser-fixture-token');
  await page.getByRole('button', {name: 'Connect'}).click();
  const app = page.getByRole('button', {name: /Demo App/});
  await expect(app).toBeVisible();

  await page.getByRole('button', {name: 'Cluster'}).click();
  await page.getByRole('button', {name: 'Vulnerable only'}).click();
  await expect(page.locator('#btn-cluster')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#btn-vuln')).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', {name: 'Refresh graph'}).click();
  await expect(page.locator('#btn-cluster')).not.toHaveClass(/active/);
  await expect(page.locator('#btn-cluster')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#btn-vuln')).not.toHaveClass(/active/);
  await expect(page.locator('#btn-vuln')).toHaveAttribute('aria-pressed', 'false');
  await expect(app).toBeVisible();

  await app.click();
  await expect(page.locator('#inspector')).toHaveClass(/open/);
  await page.evaluate(() => enterFocusMode('app'));
  await expect(page.locator('#focus-banner')).toHaveClass(/visible/);
  await page.getByRole('button', {name: 'Refresh graph'}).click();
  await expect(page.locator('#focus-banner')).not.toHaveClass(/visible/);
  await expect(page.locator('#inspector')).not.toHaveClass(/open/);
  await expect(page.locator('[aria-current="true"]')).toHaveCount(0);

  await page.getByRole('button', {name: 'Build path'}).click();
  await app.click();
  await page.getByRole('button', {name: /Full Disk Access/}).click();
  await expect(page.locator('#path-banner')).toHaveClass(/visible/);
  await page.getByRole('button', {name: 'Refresh graph'}).click();
  await expect(page.locator('#path-banner')).not.toHaveClass(/visible/);
  await expect(page.locator('#detail-empty')).toBeVisible();
});

test('live refresh keeps the newest graph when responses finish out of order', async ({page}) => {
  await page.goto(`${origin}/live`);
  await page.getByLabel('API token').fill('browser-fixture-token');
  await page.getByRole('button', {name: 'Connect'}).click();
  await expect(page.getByRole('button', {name: /Demo App/})).toBeVisible();

  const pendingGraphRoutes = [];
  await page.route('**/api/graph', route => pendingGraphRoutes.push(route));
  await page.evaluate(() => {
    liveRefresh();
    liveRefresh();
  });
  await expect.poll(() => pendingGraphRoutes.length).toBe(2);

  const olderResponse = pendingGraphRoutes.shift();
  const newerResponse = pendingGraphRoutes.shift();
  await newerResponse.fulfill({json: {
    metadata: {hostname: 'newer-graph'},
    graph: {
      nodes: [{id: 'newer', kind: 'rs_Application', label: 'Newer App', x: 300, y: 200, properties: {}}],
      edges: [],
    },
  }});
  await expect(page.getByRole('button', {name: /Newer App/})).toBeVisible();
  await expect(page.locator('#live-status')).toHaveText('Graph refreshed.');

  await olderResponse.fulfill({json: {
    metadata: {hostname: 'older-graph'},
    graph: {
      nodes: [{id: 'older', kind: 'rs_Application', label: 'Older App', x: 100, y: 100, properties: {}}],
      edges: [],
    },
  }});
  await expect(page.getByRole('button', {name: /Newer App/})).toBeVisible();
  await expect(page.getByRole('button', {name: /Older App/})).toHaveCount(0);
  await expect(page.getByRole('button', {name: /Demo App/})).toHaveCount(0);
  await expect(page.locator('#live-status')).toHaveText('Graph refreshed.');
});

test('narrow layout does not create page-level horizontal clipping', async ({page}) => {
  test.skip(test.info().project.name !== 'narrow');
  await page.goto(`${origin}/static`);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await expect(page.getByRole('tab', {name: 'Queries'})).toBeVisible();
  await expect(page.getByLabel('Theme')).toBeVisible();
  expect(await page.getByLabel('Theme').evaluate(element => element.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
});
