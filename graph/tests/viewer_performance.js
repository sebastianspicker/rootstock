const assert = require('node:assert/strict');
const fs = require('node:fs');
const {performance} = require('node:perf_hooks');
const vm = require('node:vm');

const nodes = Array.from({length: 10000}, (_, index) => ({
  id: `n${index}`,
  x: (index * 73) % 10000,
  y: (index * 191) % 10000,
  kind: index % 3 === 0 ? 'rs_Application' : 'rs_User',
  label: `Synthetic node ${index}`,
}));
const visibleNodeIds = new Set(nodes.map(node => node.id));
const nodeRadius = () => 8;
global.nodes = nodes;
global.visibleNodeIds = visibleNodeIds;
global.nodeRadius = nodeRadius;
const {SpatialGrid} = require('../../graph/viewer_spatial.js');

const index = new SpatialGrid(nodes, {isVisible: node => visibleNodeIds.has(node.id), radiusFor: nodeRadius});
const nestedHits = new SpatialGrid([
  {id: 'a', x: 0, y: 0},
  {id: 'z', x: 0, y: 0},
], {isVisible: () => true, radiusFor: () => 8});
assert.equal(nestedHits.findNearest(0, 0, 20).id, 'a',
  'overlapping clickable nodes use a deterministic id tie-break');
const nearestBoundary = new SpatialGrid([
  {id: 'near-center', x: 3, y: 0},
  {id: 'near-boundary', x: 10, y: 0},
], {isVisible: () => true, radiusFor: node => node.id === 'near-center' ? 1 : 9.5});
assert.equal(nearestBoundary.findNearest(0, 0, 20).id, 'near-boundary',
  'hit testing chooses the nearest clickable boundary, not the nearest center');
const hitDurations = [];
for (let sample = 0; sample < 2000; sample++) {
  const started = performance.now();
  index.findNearest((sample * 97) % 10000, (sample * 211) % 10000, 20);
  hitDurations.push(performance.now() - started);
}

const edges = Array.from({length: 50000}, (_, index) => ({
  source: `n${index % nodes.length}`,
  target: `n${(index * 17 + 3) % nodes.length}`,
  kind: 'rs_RELATES_TO',
  properties: {_traversable: true},
}));
const viewerSource = fs.readFileSync('viewer.js', 'utf8');
const viewerCore = viewerSource.slice(0, viewerSource.indexOf('// ── Metadata'));
const elements = new Map();
function element() {
  return {
    classList: {add() {}, remove() {}},
    setAttribute() {},
    textContent: '',
  };
}
const viewerContext = {
  DATA: undefined,
  SpatialGrid,
  document: {getElementById(id) {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  }},
  requestAnimationFrame() {},
  drawFrame() {},
  updateStats() {},
  updateRiskSummary() {},
};
vm.runInNewContext(
  viewerCore.replace('let DATA = null /* VIEWER_DATA */;', `let DATA = ${JSON.stringify({graph: {nodes, edges}})};`) +
  '\nfunction updateAccessibleNodeList() {}\n' +
  'globalThis.__viewer = {activeNodeKinds, computeVisibility, setSearchTerm(value) { searchTerm = value; }};',
  viewerContext,
);
viewerContext.__viewer.activeNodeKinds.add('rs_User');
const filterDurations = [];
for (let sample = 0; sample < 20; sample++) {
  const started = performance.now();
  const term = sample % 2 ? 'synthetic node 9' : '';
  viewerContext.__viewer.setSearchTerm(term);
  viewerContext.__viewer.computeVisibility();
  filterDurations.push(performance.now() - started);
}

function percentile(values, fraction) {
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.floor((ordered.length - 1) * fraction)];
}

const result = {
  fixture: {nodes: nodes.length, edges: edges.length},
  hitTestP95Ms: percentile(hitDurations, 0.95),
  filterP95Ms: percentile(filterDurations, 0.95),
};
assert.ok(result.hitTestP95Ms < 16, JSON.stringify(result));
assert.ok(result.filterP95Ms < 100, JSON.stringify(result));
process.stdout.write(`${JSON.stringify(result)}\n`);
