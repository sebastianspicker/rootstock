
// ── Data (with pre-computed x,y positions) ──────────────────────────────────
let DATA = {{VIEWER_DATA}};
const nodes = DATA.graph.nodes;
const edges = DATA.graph.edges;

// Build lookup
const nodeById = new Map(nodes.map(n => [n.id, n]));
// Resolve valid links
const links = edges.filter(e => nodeById.has(e.source) && nodeById.has(e.target));

// ── Safe DOM helpers ────────────────────────────────────────────────────────
function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'className') e.className = v;
    else if (k === 'textContent') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  });
  if (children) children.forEach(c => { if (c) e.appendChild(c); });
  return e;
}

function propRow(key, value) {
  const row = el('div', {className: 'prop-row'});
  row.appendChild(el('span', {className: 'prop-key', textContent: String(key)}));
  let cls = 'prop-val';
  let display;
  if (typeof value === 'boolean') {
    cls += value ? ' bool-true' : ' bool-false';
    display = value ? 'true' : 'false';
  } else if (Array.isArray(value)) {
    display = value.join(', ') || '(empty)';
  } else if (value === null || value === undefined) {
    cls += ' bool-false'; display = '(null)';
  } else { display = String(value); }
  row.appendChild(el('span', {className: cls, textContent: display}));
  return row;
}

function sectionHeader(text) {
  const h = el('h4', {textContent: text});
  return el('div', {className: 'prop-section'}, [h]);
}

// ── Derived data ────────────────────────────────────────────────────────────
const degreeMap = new Map();
links.forEach(l => {
  degreeMap.set(l.source, (degreeMap.get(l.source) || 0) + 1);
  degreeMap.set(l.target, (degreeMap.get(l.target) || 0) + 1);
});

function searchableNodeText(node) {
  return [
    node.label,
    node.properties?.bundle_id,
    node.properties?.name,
    node.properties?.service,
  ].filter(Boolean).join('\n').toLowerCase();
}

const searchTextById = new Map(nodes.map(node => [node.id, searchableNodeText(node)]));

function nodeRadius(d) {
  const degree = degreeMap.get(d.id) || 0;
  return Math.min(4 + Math.sqrt(degree) * 3, 24);
}

// Node kinds with colors
const kindMeta = new Map();
nodes.forEach(n => {
  if (!kindMeta.has(n.kind)) {
    kindMeta.set(n.kind, {
      color: n.properties?._color || '#888',
      count: 0,
      label: n.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim()
    });
  }
  kindMeta.get(n.kind).count++;
});

// Edge kinds
const edgeKinds = new Map();
links.forEach(l => {
  if (!edgeKinds.has(l.kind)) {
    edgeKinds.set(l.kind, {
      label: l.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim(),
      traversable: l.properties?._traversable ?? false,
      count: 0
    });
  }
  edgeKinds.get(l.kind).count++;
});

// Adjacency lists for fast neighbor lookup
const adjOut = new Map();  // source -> [{target, link}]
const adjIn = new Map();   // target -> [{source, link}]
links.forEach(l => {
  if (!adjOut.has(l.source)) adjOut.set(l.source, []);
  adjOut.get(l.source).push({target: l.target, link: l});
  if (!adjIn.has(l.target)) adjIn.set(l.target, []);
  adjIn.get(l.target).push({source: l.source, link: l});
});

// ── Progressive disclosure: default visibility ──────────────────────────────
// Only Applications visible on first load; others can be toggled on
const DEFAULT_VISIBLE_KINDS = new Set(['Application', 'rs_Application']);

// ── State ───────────────────────────────────────────────────────────────────
let showLabels = true;
let attackPathMode = false;
const activeNodeKinds = new Set(DEFAULT_VISIBLE_KINDS);
const activeEdgeKinds = new Set(edgeKinds.keys());
let selectedNode = null;
let searchTerm = '';
let hoverNode = null;
let pinnedNode = null;  // Click to pin neighbor highlight
let focusNodeId = null;
let pathMode = false;
let pathSource = null;
let pathTarget = null;
let pathResult = null;
let clusterByType = false;
let dragNode = null;
let dirty = true;
let didDrag = false;  // Suppress click after pan/drag
let mouseDownPos = {x: 0, y: 0};

function rebuildDerivedData(resetFilters = false) {
  nodeById.clear();
  nodes.forEach((n, i) => nodeById.set(n.id, n));

  searchTextById.clear();
  nodes.forEach(node => searchTextById.set(node.id, searchableNodeText(node)));

  links.splice(0, links.length, ...edges.filter(e => nodeById.has(e.source) && nodeById.has(e.target)));

  degreeMap.clear();
  links.forEach(l => {
    degreeMap.set(l.source, (degreeMap.get(l.source) || 0) + 1);
    degreeMap.set(l.target, (degreeMap.get(l.target) || 0) + 1);
  });

  kindMeta.clear();
  nodes.forEach(n => {
    if (!kindMeta.has(n.kind)) {
      kindMeta.set(n.kind, {
        color: n.properties?._color || '#888',
        count: 0,
        label: n.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim()
      });
    }
    kindMeta.get(n.kind).count++;
  });

  edgeKinds.clear();
  links.forEach(l => {
    if (!edgeKinds.has(l.kind)) {
      edgeKinds.set(l.kind, {
        label: l.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim(),
        traversable: l.properties?._traversable ?? false,
        count: 0
      });
    }
    edgeKinds.get(l.kind).count++;
  });

  adjOut.clear();
  adjIn.clear();
  links.forEach(l => {
    if (!adjOut.has(l.source)) adjOut.set(l.source, []);
    adjOut.get(l.source).push({target: l.target, link: l});
    if (!adjIn.has(l.target)) adjIn.set(l.target, []);
    adjIn.get(l.target).push({source: l.source, link: l});
  });

  if (resetFilters) {
    activeEdgeKinds.clear();
    edgeKinds.forEach((_info, kind) => activeEdgeKinds.add(kind));
    if (![...activeNodeKinds].some(kind => kindMeta.has(kind))) {
      activeNodeKinds.clear();
      DEFAULT_VISIBLE_KINDS.forEach(kind => {
        if (kindMeta.has(kind)) activeNodeKinds.add(kind);
      });
    }
    buildFilters();
  }

  document.getElementById('node-count').textContent = nodes.length;
  document.getElementById('edge-count').textContent = links.length;
  const currentMeta = DATA.metadata || {};
  document.getElementById('meta-info').textContent =
    [currentMeta.hostname, currentMeta.generated_at?.split('T')[0]].filter(Boolean).join(' \u2014 ');
  computeVisibility();
  if (typeof updateStats === 'function') updateStats();
  if (typeof updateRiskSummary === 'function') updateRiskSummary();
  if (typeof spatialIndex !== 'undefined') spatialIndex = new SpatialGrid(nodes);
  markDirty();
}

function replaceGraphData(data) {
  DATA = data;
  nodes.splice(0, nodes.length, ...(data.graph?.nodes || []));
  edges.splice(0, edges.length, ...(data.graph?.edges || []));
  rebuildDerivedData(true);
}

// Transform state (pan/zoom)
let transform = {x: 0, y: 0, k: 1};

// ── Visibility computation ──────────────────────────────────────────────────
let visibleNodeIds = new Set();
let visibleLinkSet = new Set();

function computeVisibility() {
  // Path result takes priority
  if (pathMode && pathResult) {
    visibleNodeIds = pathResult.nodeIds;
    visibleLinkSet = new Set();
    links.forEach((l, i) => {
      if (pathResult.linkKeys.has(linkKey(l))) visibleLinkSet.add(i);
    });
    updateAccessibleNodeList();
    return;
  }

  // Focus mode: node + 1-hop neighbors
  if (focusNodeId) {
    visibleNodeIds = new Set([focusNodeId]);
    visibleLinkSet = new Set();
    links.forEach((l, i) => {
      if (l.source === focusNodeId || l.target === focusNodeId) {
        visibleNodeIds.add(l.source);
        visibleNodeIds.add(l.target);
        visibleLinkSet.add(i);
      }
    });
    updateAccessibleNodeList();
    return;
  }

  // Normal: kind filter + search filter
  visibleNodeIds = new Set();
  nodes.forEach(n => {
    const kindOk = activeNodeKinds.has(n.kind);
    const searchOk = !searchTerm || searchTextById.get(n.id)?.includes(searchTerm);
    if (kindOk && searchOk) visibleNodeIds.add(n.id);
  });

  visibleLinkSet = new Set();
  links.forEach((l, i) => {
    if (!visibleNodeIds.has(l.source) || !visibleNodeIds.has(l.target)) return;
    if (!activeEdgeKinds.has(l.kind)) return;
    if (attackPathMode && !l.properties?._traversable) return;
    visibleLinkSet.add(i);
  });
  updateAccessibleNodeList();
}

let frameRequested = false;
function markDirty() {
  dirty = true;
  if (!frameRequested) {
    frameRequested = true;
    requestAnimationFrame(draw);
  }
}

function linkKey(l) { return l.source + '>' + l.kind + '>' + l.target; }

// ── Metadata ────────────────────────────────────────────────────────────────
const meta = DATA.metadata || {};
document.getElementById('meta-info').textContent =
  [meta.hostname, meta.generated_at?.split('T')[0]].filter(Boolean).join(' \u2014 ');
document.getElementById('node-count').textContent = nodes.length;
document.getElementById('edge-count').textContent = links.length;

// ── Filters ─────────────────────────────────────────────────────────────────
function buildFilters() {
  const nf = document.getElementById('node-filters');
  nf.textContent = '';
  [...kindMeta.entries()].sort((a,b) => b[1].count - a[1].count).forEach(([kind, info]) => {
    const cb = el('input', {type: 'checkbox', 'data-kind': kind});
    cb.checked = activeNodeKinds.has(kind);
    cb.addEventListener('change', e => {
      if (e.target.checked) activeNodeKinds.add(kind);
      else activeNodeKinds.delete(kind);
      computeVisibility(); markDirty();
    });
    const dot = el('span', {className: 'color-dot'});
    dot.style.background = info.color;
    nf.appendChild(el('label', {className: 'filter-item'}, [
      cb, dot,
      el('span', {textContent: info.label}),
      el('span', {className: 'filter-count', textContent: String(info.count)})
    ]));
  });

  const ef = document.getElementById('edge-filters');
  ef.textContent = '';
  const travCount = [...edgeKinds.values()].filter(e => e.traversable).reduce((s,e) => s + e.count, 0);
  const nonTravCount = [...edgeKinds.values()].filter(e => !e.traversable).reduce((s,e) => s + e.count, 0);

  const travCb = el('input', {type: 'checkbox', id: 'filter-trav'});
  travCb.checked = true;
  travCb.addEventListener('change', e => {
    edgeKinds.forEach((info, kind) => {
      if (info.traversable) {
        if (e.target.checked) activeEdgeKinds.add(kind);
        else activeEdgeKinds.delete(kind);
      }
    });
    computeVisibility(); markDirty();
  });
  ef.appendChild(el('label', {className: 'filter-item'}, [
    travCb, el('span', {textContent: 'Traversable (attack)'}),
    el('span', {className: 'filter-count', textContent: String(travCount)})
  ]));

  const nonTravCb = el('input', {type: 'checkbox', id: 'filter-nontrav'});
  nonTravCb.checked = true;
  nonTravCb.addEventListener('change', e => {
    edgeKinds.forEach((info, kind) => {
      if (!info.traversable) {
        if (e.target.checked) activeEdgeKinds.add(kind);
        else activeEdgeKinds.delete(kind);
      }
    });
    computeVisibility(); markDirty();
  });
  ef.appendChild(el('label', {className: 'filter-item'}, [
    nonTravCb, el('span', {textContent: 'Non-traversable (info)'}),
    el('span', {className: 'filter-count', textContent: String(nonTravCount)})
  ]));
}
buildFilters();

function updateAccessibleNodeList() {
  const list = document.getElementById('node-list');
  if (!list) return;
  const visible = pathMode && !pathResult
    ? nodes
    : nodes.filter(node => visibleNodeIds.has(node.id));
  list.textContent = '';
  const fragment = document.createDocumentFragment();
  visible.forEach(node => {
    const info = kindMeta.get(node.kind) || {};
    const button = el('button', {
      type: 'button',
      className: 'node-list-button',
      'aria-current': selectedNode?.id === node.id ? 'true' : 'false',
      onclick: () => {
        if (pathMode) handlePathClick(node);
        else {
          selectedNode = node;
          pinnedNode = node;
          inspectNode(node);
          centerOnNode(node);
        }
        updateAccessibleNodeList();
      }
    }, [
      el('span', {className: 'color-dot', 'aria-hidden': 'true'}),
      el('span', {className: 'node-list-label', textContent: node.label || node.id}),
      el('span', {className: 'node-list-kind', textContent: info.label || node.kind})
    ]);
    button.querySelector('.color-dot').style.background = info.color || '#8c99a8';
    fragment.appendChild(el('li', null, [button]));
  });
  list.appendChild(fragment);
  document.getElementById('node-list-count').textContent = visible.length + ' visible';
  document.getElementById('node-list-empty').hidden = visible.length !== 0;
  const status = document.getElementById('search-status');
  if (nodes.length === 0) status.textContent = 'The graph is empty.';
  else if (visible.length === 0) status.textContent = 'No nodes match the current search and filters.';
  else status.textContent = visible.length + ' of ' + nodes.length + ' nodes visible.';
}

// ── Search ──────────────────────────────────────────────────────────────────
document.getElementById('search').addEventListener('input', e => {
  searchTerm = e.target.value.toLowerCase();
  computeVisibility(); markDirty();
});

// ── Canvas setup ────────────────────────────────────────────────────────────
const container = document.getElementById('graph-container');
const canvas = document.getElementById('graph-canvas');
const ctx = canvas.getContext('2d');
let W, H, dpr;

function resizeCanvas() {
  dpr = window.devicePixelRatio || 1;
  W = container.clientWidth;
  H = container.clientHeight;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  canvas.style.width = W + 'px';
  canvas.style.height = H + 'px';
  markDirty();
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);
if ('ResizeObserver' in window) new ResizeObserver(resizeCanvas).observe(container);

// ── Spatial grid for bounded hit-testing ────────────────────────────────────
class SpatialGrid {
  constructor(nodes) {
    this.cellSize = 64;
    this.cells = new Map();
    nodes.forEach(node => {
      const key = this.key(node.x, node.y);
      if (!this.cells.has(key)) this.cells.set(key, []);
      this.cells.get(key).push(node);
    });
  }

  key(x, y) {
    return Math.floor(x / this.cellSize) + ':' + Math.floor(y / this.cellSize);
  }

  findNearest(px, py, maxDist) {
    let best = null;
    let bestDist = maxDist * maxDist;
    const radius = Math.ceil((maxDist + 24) / this.cellSize);
    const cx = Math.floor(px / this.cellSize);
    const cy = Math.floor(py / this.cellSize);
    const candidates = [];
    for (let x = cx - radius; x <= cx + radius; x++) {
      for (let y = cy - radius; y <= cy + radius; y++) {
        candidates.push(...(this.cells.get(x + ':' + y) || []));
      }
    }
    for (const n of candidates) {
      if (!visibleNodeIds.has(n.id)) continue;
      const dx = n.x - px;
      const dy = n.y - py;
      const r = nodeRadius(n);
      const d = dx * dx + dy * dy;
      if (d < (r + maxDist) * (r + maxDist) && d < bestDist + r * r) {
        const actualDist = Math.sqrt(d) - r;
        if (actualDist < Math.sqrt(bestDist)) {
          bestDist = actualDist * actualDist;
          best = n;
        }
      }
    }
    return best;
  }
}

let spatialIndex = new SpatialGrid(nodes);

// ── Transform helpers ───────────────────────────────────────────────────────
function screenToWorld(sx, sy) {
  return {
    x: (sx - transform.x) / transform.k,
    y: (sy - transform.y) / transform.k
  };
}

function worldToScreen(wx, wy) {
  return {
    x: wx * transform.k + transform.x,
    y: wy * transform.k + transform.y
  };
}

// ── Pan & Zoom (mouse/trackpad) ─────────────────────────────────────────────
let isPanning = false;
let panStart = {x: 0, y: 0};

canvas.addEventListener('wheel', e => {
  e.preventDefault();
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  // Zoom around mouse position
  const zoomFactor = e.deltaY > 0 ? 0.92 : 1.08;
  const newK = Math.max(0.05, Math.min(20, transform.k * zoomFactor));
  const ratio = newK / transform.k;
  transform.x = mx - (mx - transform.x) * ratio;
  transform.y = my - (my - transform.y) * ratio;
  transform.k = newK;
  markDirty();
}, {passive: false});

canvas.addEventListener('mousedown', e => {
  if (e.button === 2) return; // right-click handled separately
  didDrag = false;
  mouseDownPos = {x: e.clientX, y: e.clientY};
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(mx, my);

  // Check if clicking a node
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);
  if (hit) {
    dragNode = hit;
    dragNode._dragOffsetX = world.x - hit.x;
    dragNode._dragOffsetY = world.y - hit.y;
    canvas.style.cursor = 'grabbing';
  } else {
    isPanning = true;
    panStart = {x: e.clientX - transform.x, y: e.clientY - transform.y};
    canvas.style.cursor = 'grabbing';
  }
});

canvas.addEventListener('mousemove', e => {
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  // Detect drag (moved more than 4px from mousedown)
  if (!didDrag && (dragNode || isPanning)) {
    const dx = e.clientX - mouseDownPos.x;
    const dy = e.clientY - mouseDownPos.y;
    if (dx * dx + dy * dy > 16) didDrag = true;
  }

  if (dragNode) {
    const world = screenToWorld(mx, my);
    dragNode.x = world.x - dragNode._dragOffsetX;
    dragNode.y = world.y - dragNode._dragOffsetY;
    markDirty();
    return;
  }

  if (isPanning) {
    transform.x = e.clientX - panStart.x;
    transform.y = e.clientY - panStart.y;
    markDirty();
    return;
  }

  // Hover detection
  const world = screenToWorld(mx, my);
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);
  if (hit !== hoverNode) {
    hoverNode = hit;
    canvas.style.cursor = hit ? 'pointer' : 'default';
    if (hit) showTooltip(e, hit);
    else hideTooltip();
    markDirty();
  } else if (hit) {
    // Update tooltip position
    const tooltip = document.getElementById('tooltip');
    tooltip.style.left = (mx + 16) + 'px';
    tooltip.style.top = (my - 8) + 'px';
  }
});

canvas.addEventListener('mouseup', e => {
  if (dragNode) {
    // If barely moved, treat as click
    dragNode = null;
    spatialIndex = new SpatialGrid(nodes);
    canvas.style.cursor = 'default';
    markDirty();
    return;
  }
  if (isPanning) {
    isPanning = false;
    canvas.style.cursor = 'default';
  }
});

canvas.addEventListener('click', e => {
  // Ignore click if it was actually a pan/drag
  if (didDrag) return;

  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(mx, my);
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);

  hideContextMenu();

  if (hit) {
    if (pathMode) { handlePathClick(hit); return; }
    // Toggle pin: click same node unpins, different node re-pins
    if (pinnedNode && pinnedNode.id === hit.id) {
      pinnedNode = null;
      selectedNode = null;
      closeInspector();
    } else {
      pinnedNode = hit;
      selectedNode = hit;
      inspectNode(hit);
    }
  } else {
    if (pathMode) return;
    pinnedNode = null;
    selectedNode = null;
    closeInspector();
  }
  markDirty();
});

canvas.addEventListener('contextmenu', e => {
  e.preventDefault();
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(mx, my);
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);
  if (hit) showContextMenu(e, hit);
});

// ── Node shapes ─────────────────────────────────────────────────────────────
// Maps node kind prefixes to distinct shapes for visual identification.
// Shapes: circle (default), diamond (vulnerabilities/threats), hexagon (security),
// square (infrastructure), triangle (users/groups), roundrect (services)
const SHAPE_MAP = {
  'rs_Vulnerability': 'diamond',
  'rs_AttackTechnique': 'diamond',
  'rs_ThreatGroup': 'diamond',
  'rs_CWE': 'diamond',
  'rs_TCCPermission': 'hexagon',
  'rs_Entitlement': 'hexagon',
  'rs_AuthRight': 'hexagon',
  'rs_SandboxProfile': 'hexagon',
  'rs_User': 'triangle',
  'rs_LocalGroup': 'triangle',
  'rs_ADUser': 'triangle',
  'rs_ADGroup': 'triangle',
  'rs_Computer': 'square',
  'rs_CriticalFile': 'square',
  'rs_Firewall': 'square',
  'rs_XPCService': 'roundrect',
  'rs_LaunchItem': 'roundrect',
  'rs_RemoteAccess': 'roundrect',
  'rs_LoginSession': 'roundrect',
  'rs_SystemExt': 'roundrect',
  'rs_Recommendation': 'roundrect',
};

function drawNodeShape(ctx, x, y, r, shape) {
  switch (shape) {
    case 'diamond': {
      const s = r * 1.3;
      ctx.moveTo(x, y - s);
      ctx.lineTo(x + s, y);
      ctx.lineTo(x, y + s);
      ctx.lineTo(x - s, y);
      ctx.closePath();
      break;
    }
    case 'hexagon': {
      const s = r * 1.1;
      for (let i = 0; i < 6; i++) {
        const angle = Math.PI / 6 + (Math.PI / 3) * i;
        const px = x + s * Math.cos(angle);
        const py = y + s * Math.sin(angle);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      break;
    }
    case 'square': {
      const s = r * 0.9;
      const cr = s * 0.2; // corner radius
      ctx.moveTo(x - s + cr, y - s);
      ctx.lineTo(x + s - cr, y - s);
      ctx.arcTo(x + s, y - s, x + s, y - s + cr, cr);
      ctx.lineTo(x + s, y + s - cr);
      ctx.arcTo(x + s, y + s, x + s - cr, y + s, cr);
      ctx.lineTo(x - s + cr, y + s);
      ctx.arcTo(x - s, y + s, x - s, y + s - cr, cr);
      ctx.lineTo(x - s, y - s + cr);
      ctx.arcTo(x - s, y - s, x - s + cr, y - s, cr);
      ctx.closePath();
      break;
    }
    case 'triangle': {
      const s = r * 1.2;
      ctx.moveTo(x, y - s);
      ctx.lineTo(x + s * 0.87, y + s * 0.5);
      ctx.lineTo(x - s * 0.87, y + s * 0.5);
      ctx.closePath();
      break;
    }
    case 'roundrect': {
      const w = r * 1.5, h = r * 0.9, cr = r * 0.35;
      ctx.moveTo(x - w + cr, y - h);
      ctx.lineTo(x + w - cr, y - h);
      ctx.arcTo(x + w, y - h, x + w, y - h + cr, cr);
      ctx.lineTo(x + w, y + h - cr);
      ctx.arcTo(x + w, y + h, x + w - cr, y + h, cr);
      ctx.lineTo(x - w + cr, y + h);
      ctx.arcTo(x - w, y + h, x - w, y + h - cr, cr);
      ctx.lineTo(x - w, y - h + cr);
      ctx.arcTo(x - w, y - h, x - w + cr, y - h, cr);
      ctx.closePath();
      break;
    }
    default: // circle
      ctx.arc(x, y, r, 0, Math.PI * 2);
  }
}

function getNodeShape(kind) {
  return SHAPE_MAP[kind] || 'circle';
}

// ── Drawing ─────────────────────────────────────────────────────────────────
const ARROW_SIZE = 6;

function draw() {
  frameRequested = false;
  if (!dirty) return;
  dirty = false;

  ctx.save();
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--canvas').trim() || '#0b1016';
  ctx.fillRect(0, 0, W, H);

  // Apply transform
  ctx.translate(transform.x, transform.y);
  ctx.scale(transform.k, transform.k);

  // Viewport bounds in world coordinates (for culling)
  const vp = {
    x0: -transform.x / transform.k - 100,
    y0: -transform.y / transform.k - 100,
    x1: (W - transform.x) / transform.k + 100,
    y1: (H - transform.y) / transform.k + 100
  };

  // ── Draw edges ──────────────────────────────────────────────────────────
  // Pinned node takes priority over hover for neighbor highlighting
  const highlightNode = (!pathMode && !focusNodeId) ? (pinnedNode || hoverNode) : null;
  const isNeighborHighlight = !!highlightNode;
  let hoverNeighborNodes, hoverNeighborLinks;
  if (isNeighborHighlight) {
    hoverNeighborNodes = new Set([highlightNode.id]);
    hoverNeighborLinks = new Set();
    (adjOut.get(highlightNode.id) || []).forEach(e => { hoverNeighborNodes.add(e.target); hoverNeighborLinks.add(e.link); });
    (adjIn.get(highlightNode.id) || []).forEach(e => { hoverNeighborNodes.add(e.source); hoverNeighborLinks.add(e.link); });
  }

  links.forEach((l, i) => {
    const visible = visibleLinkSet.has(i);
    if (!visible && !isNeighborHighlight) return;

    const src = nodeById.get(l.source);
    const tgt = nodeById.get(l.target);
    if (!src || !tgt) return;

    // Viewport culling for edges
    const minX = Math.min(src.x, tgt.x);
    const maxX = Math.max(src.x, tgt.x);
    const minY = Math.min(src.y, tgt.y);
    const maxY = Math.max(src.y, tgt.y);
    if (maxX < vp.x0 || minX > vp.x1 || maxY < vp.y0 || minY > vp.y1) return;

    const trav = l.properties?._traversable;
    let alpha = visible ? (trav ? 0.5 : 0.2) : 0.03;
    let color = trav ? '#58a6ff' : '#30363d';
    let width = trav ? 1.5 : 0.7;
    let dashPattern = null;

    // Path highlight
    if (pathMode && pathResult && pathResult.linkKeys.has(linkKey(l))) {
      color = '#f85149'; alpha = 1; width = 3;
    }

    // Neighbor highlight
    if (isNeighborHighlight) {
      if (hoverNeighborLinks.has(l)) {
        alpha = 0.85; width = trav ? 2.5 : 1.5;
        color = trav ? '#79c0ff' : '#8b949e';
      } else {
        alpha = 0.03;
      }
    }

    // Inferred edges get dashed style
    if (!trav && visible && alpha > 0.05) {
      dashPattern = [4 / transform.k, 3 / transform.k];
    }

    ctx.beginPath();
    if (dashPattern) ctx.setLineDash(dashPattern);
    else ctx.setLineDash([]);
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = color;
    ctx.globalAlpha = alpha;
    ctx.lineWidth = width / transform.k;
    ctx.stroke();
    ctx.setLineDash([]);

    // Arrow (directional indicator)
    if (transform.k > 0.3) {
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist > 0) {
        const tr = nodeRadius(tgt);
        const ax = tgt.x - (dx / dist) * (tr + 2);
        const ay = tgt.y - (dy / dist) * (tr + 2);
        const angle = Math.atan2(dy, dx);
        const as = ARROW_SIZE / transform.k;
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - as * Math.cos(angle - 0.4), ay - as * Math.sin(angle - 0.4));
        ctx.lineTo(ax - as * Math.cos(angle + 0.4), ay - as * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = color;
        ctx.fill();
      }
    }
  });

  ctx.globalAlpha = 1;

  // ── Draw nodes ──────────────────────────────────────────────────────────
  const labelThreshold = 0.4;  // Zoom level above which labels appear
  const showAllLabels = showLabels && transform.k >= labelThreshold;
  const showHighDegreeLabels = showLabels && transform.k >= 0.2 && transform.k < labelThreshold;

  nodes.forEach(n => {
    // Viewport culling
    if (n.x < vp.x0 || n.x > vp.x1 || n.y < vp.y0 || n.y > vp.y1) return;

    const isVisible = visibleNodeIds.has(n.id);
    if (!isVisible && !isNeighborHighlight) return;

    const r = nodeRadius(n);
    const color = n.properties?._color || kindMeta.get(n.kind)?.color || '#888';
    let alpha = isVisible ? 1 : 0.1;

    if (isNeighborHighlight) {
      alpha = hoverNeighborNodes.has(n.id) ? 1 : 0.08;
    }

    // Path highlighting
    let strokeColor = '#21262d';
    let strokeWidth = 1.5 / transform.k;
    if (pathMode && pathResult) {
      if (n.id === pathSource) { strokeColor = '#3fb950'; strokeWidth = 3 / transform.k; }
      else if (n.id === pathTarget) { strokeColor = '#f85149'; strokeWidth = 3 / transform.k; }
      else if (pathResult.nodeIds.has(n.id)) { strokeColor = '#f85149'; strokeWidth = 2 / transform.k; }
    }
    if (selectedNode && n.id === selectedNode.id) {
      strokeColor = '#f0f6fc'; strokeWidth = 2.5 / transform.k;
    }

    ctx.globalAlpha = alpha;

    // Risk-level and owned glow
    const riskLevel = n.properties?.risk_level;
    if (n.properties?.owned) {
      ctx.shadowColor = '#ffd700';
      ctx.shadowBlur = 14 / transform.k;
    } else if (riskLevel === 'critical') {
      ctx.shadowColor = '#f85149';
      ctx.shadowBlur = 10 / transform.k;
    } else if (riskLevel === 'high') {
      ctx.shadowColor = '#d29922';
      ctx.shadowBlur = 8 / transform.k;
    }

    // Draw node shape
    const shape = getNodeShape(n.kind);
    ctx.beginPath();
    drawNodeShape(ctx, n.x, n.y, r, shape);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = strokeWidth;
    ctx.stroke();

    ctx.shadowColor = 'transparent';
    ctx.shadowBlur = 0;

    // Risk score ring indicator (visible at moderate zoom)
    if (n.properties?.risk_score != null && transform.k > 0.25) {
      const score = n.properties.risk_score;
      if (score >= 25) {
        const ringColor = score >= 75 ? '#f85149' : score >= 50 ? '#d29922' : '#58a6ff';
        const ringAlpha = Math.min(0.8, score / 100);
        // Draw a partial arc proportional to risk score
        const arcEnd = (score / 100) * Math.PI * 2;
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 4 / transform.k, -Math.PI / 2, -Math.PI / 2 + arcEnd);
        ctx.strokeStyle = ringColor;
        ctx.globalAlpha = alpha * ringAlpha;
        ctx.lineWidth = 2.5 / transform.k;
        ctx.stroke();
        ctx.globalAlpha = alpha;
      }
    }

    // Vulnerability border ring (KEV = red pulse, high-EPSS = orange)
    const vulnEdges = (adjOut.get(n.id) || []).filter(e => e.link.kind === 'rs_AffectedBy');
    if (vulnEdges.length > 0 && transform.k > 0.2) {
      let hasKev = false, hasHighEpss = false;
      vulnEdges.forEach(({target}) => {
        const vn = nodeById.get(target);
        if (vn) {
          if (vn.properties?.in_kev) hasKev = true;
          if (vn.properties?.epss_score > 0.5) hasHighEpss = true;
        }
      });
      if (hasKev || hasHighEpss) {
        const ringColor = hasKev ? '#f85149' : '#d29922';
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + 3 / transform.k, 0, Math.PI * 2);
        ctx.strokeStyle = ringColor;
        ctx.lineWidth = 2 / transform.k;
        ctx.setLineDash([3 / transform.k, 2 / transform.k]);
        ctx.stroke();
        ctx.setLineDash([]);
      }
    }

    // Tier badge
    if (n.properties?.tier != null && transform.k > 0.3) {
      const tierColors = {'0': '#f85149', '1': '#d29922', '2': '#58a6ff'};
      const tierColor = tierColors[String(n.properties.tier)] || '#8b949e';
      // Small badge circle at top-right of node
      const bx = n.x + r * 0.65, by = n.y - r * 0.65;
      const br = Math.max(5, 6 / transform.k);
      ctx.beginPath();
      ctx.arc(bx, by, br, 0, Math.PI * 2);
      ctx.fillStyle = tierColor;
      ctx.fill();
      ctx.fillStyle = '#fff';
      ctx.font = `bold ${Math.max(6, 6 / transform.k)}px -apple-system, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(String(n.properties.tier), bx, by + 0.5);
    }

    // Labels (semantic zoom)
    const shouldLabel = showAllLabels ||
      (showHighDegreeLabels && (degreeMap.get(n.id) || 0) > 5) ||
      (hoverNode && hoverNode.id === n.id) ||
      (selectedNode && selectedNode.id === n.id) ||
      (pathMode && pathResult && (n.id === pathSource || n.id === pathTarget));

    if (shouldLabel && n.label) {
      const fontSize = Math.max(9, Math.min(12, 10 / transform.k));
      ctx.font = `500 ${fontSize}px -apple-system, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      // Label background pill for readability
      const label = n.label.length > 24 ? n.label.slice(0, 23) + '\u2026' : n.label;
      const lw = ctx.measureText(label).width;
      const ly = n.y + r + 4;
      ctx.fillStyle = 'rgba(13,17,23,.75)';
      ctx.beginPath();
      const pad = 3, rr = 3;
      ctx.roundRect(n.x - lw/2 - pad, ly - 1, lw + pad*2, fontSize + 3, rr);
      ctx.fill();
      ctx.fillStyle = '#c9d1d9';
      ctx.fillText(label, n.x, ly);
    }
  });

  // ── Edge labels (visible on hover or path) ────────────────────────────
  if (transform.k > 0.5) {
    ctx.globalAlpha = 0.85;
    const edgeFontSize = Math.max(8, 9 / transform.k);
    ctx.font = `500 ${edgeFontSize}px -apple-system, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    function drawEdgeLabel(src, tgt, text, color) {
      const mx = (src.x + tgt.x) / 2;
      const my = (src.y + tgt.y) / 2;
      // Background pill
      const tw = ctx.measureText(text).width;
      ctx.fillStyle = 'rgba(13,17,23,.8)';
      ctx.beginPath();
      ctx.roundRect(mx - tw/2 - 4, my - edgeFontSize/2 - 2, tw + 8, edgeFontSize + 4, 3);
      ctx.fill();
      ctx.fillStyle = color;
      ctx.fillText(text, mx, my);
    }

    if (isNeighborHighlight) {
      hoverNeighborLinks.forEach(l => {
        const src = nodeById.get(l.source);
        const tgt = nodeById.get(l.target);
        if (src && tgt) {
          const info = edgeKinds.get(l.kind);
          drawEdgeLabel(src, tgt, info?.label || l.kind, '#c9d1d9');
        }
      });
    }
    if (pathMode && pathResult) {
      links.forEach(l => {
        if (pathResult.linkKeys.has(linkKey(l))) {
          const src = nodeById.get(l.source);
          const tgt = nodeById.get(l.target);
          if (src && tgt) {
            const info = edgeKinds.get(l.kind);
            drawEdgeLabel(src, tgt, info?.label || l.kind, '#f85149');
          }
        }
      });
    }
  }

  ctx.globalAlpha = 1;
  ctx.restore();
}

markDirty();

// ── Tooltip ─────────────────────────────────────────────────────────────────
const tooltip = document.getElementById('tooltip');
function showTooltip(event, d) {
  const m = kindMeta.get(d.kind) || {};
  tooltip.hidden = false;
  tooltip.textContent = '';

  // Label
  const labelDiv = el('div', {className: 'tt-label', textContent: d.label || '?'});
  tooltip.appendChild(labelDiv);

  // Kind with color dot
  const kindDiv = el('div', {className: 'tt-kind'});
  const dot = el('span');
  dot.style.cssText = 'display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle;background:' + (m.color || '#8b949e');
  kindDiv.appendChild(dot);
  kindDiv.appendChild(el('span', {textContent: m.label || d.kind}));

  // Risk badges
  if (d.properties?.owned) {
    const badge = el('span', {className: 'tt-risk owned', textContent: 'OWNED'});
    kindDiv.appendChild(badge);
  }
  if (d.properties?.tier === 0) {
    const badge = el('span', {className: 'tt-risk critical', textContent: 'TIER 0'});
    kindDiv.appendChild(badge);
  } else if (d.properties?.tier === 1) {
    const badge = el('span', {className: 'tt-risk high', textContent: 'TIER 1'});
    kindDiv.appendChild(badge);
  } else if (d.properties?.tier === 2) {
    const badge = el('span', {className: 'tt-risk medium', textContent: 'TIER 2'});
    kindDiv.appendChild(badge);
  }
  // Risk level badge
  const riskLevel = d.properties?.risk_level;
  if (riskLevel) {
    const riskClass = riskLevel === 'critical' ? 'critical' : riskLevel === 'high' ? 'high'
      : riskLevel === 'medium' ? 'medium' : 'low';
    const badge = el('span', {className: 'tt-risk ' + riskClass,
      textContent: riskLevel.toUpperCase()});
    kindDiv.appendChild(badge);
  }
  // Risk score numeric display
  if (d.properties?.risk_score != null) {
    const score = d.properties.risk_score;
    const scoreColor = score >= 75 ? '#f85149' : score >= 50 ? '#d29922'
      : score >= 25 ? '#58a6ff' : '#3fb950';
    const scoreBadge = el('span', {className: 'tt-score', textContent: String(score)});
    scoreBadge.style.background = scoreColor + '25';
    scoreBadge.style.color = scoreColor;
    scoreBadge.style.border = '1px solid ' + scoreColor + '40';
    kindDiv.appendChild(scoreBadge);
  }
  tooltip.appendChild(kindDiv);

  // Detail section
  const degree = degreeMap.get(d.id) || 0;
  const vulnCount = (adjOut.get(d.id) || []).filter(e => e.link.kind === 'rs_AffectedBy').length;
  const detailParts = [];
  if (degree > 0) detailParts.push(degree + ' connections');
  if (vulnCount > 0) detailParts.push(vulnCount + ' CVE' + (vulnCount > 1 ? 's' : ''));
  if (d.properties?.injectable) detailParts.push('[!] Injectable');
  if (d.properties?.hardened_runtime === false) detailParts.push('[!] No hardened runtime');
  if (d.properties?.sandboxed === false) detailParts.push('[!] Not sandboxed');
  if (d.properties?.bundle_id) detailParts.push(d.properties.bundle_id);

  if (detailParts.length) {
    const detailDiv = el('div', {className: 'tt-detail', textContent: detailParts.join(' \u00b7 ')});
    tooltip.appendChild(detailDiv);
  }

  tooltip.classList.add('visible');
  const rect = container.getBoundingClientRect();
  // Smart positioning: avoid going off-screen
  let tx = event.clientX - rect.left + 16;
  let ty = event.clientY - rect.top - 8;
  if (tx + 320 > rect.width) tx = event.clientX - rect.left - 330;
  if (ty + 100 > rect.height) ty = rect.height - 110;
  tooltip.style.left = tx + 'px';
  tooltip.style.top = ty + 'px';
}
function hideTooltip() {
  tooltip.classList.remove('visible');
  tooltip.hidden = true;
}

// ── BFS shortest path ───────────────────────────────────────────────────────
function bfsShortestPath(sourceId, targetId) {
  const visited = new Set([sourceId]);
  const parent = new Map();
  const queue = [sourceId];
  let found = false;

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === targetId) { found = true; break; }
    const neighbors = adjOut.get(current) || [];
    for (const {target, link} of neighbors) {
      if (!activeEdgeKinds.has(link.kind)) continue;
      if (!link.properties?._traversable) continue;
      if (!visited.has(target)) {
        visited.add(target);
        parent.set(target, {from: current, link});
        queue.push(target);
      }
    }
  }

  if (!found) return null;

  const nodeIds = new Set();
  const linkKeys = new Set();
  const hops = [];
  let cur = targetId;
  while (parent.has(cur)) {
    const {from, link} = parent.get(cur);
    nodeIds.add(cur);
    linkKeys.add(linkKey(link));
    hops.unshift({from, to: cur, edge: link});
    cur = from;
  }
  nodeIds.add(sourceId);
  return {nodeIds, linkKeys, hops};
}

// ── Path mode ───────────────────────────────────────────────────────────────
function togglePathMode() {
  if (pathMode) { exitPathMode(); return; }
  exitFocusMode();
  pathMode = true; pathSource = null; pathTarget = null; pathResult = null;
  document.getElementById('btn-path').classList.add('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'true');
  document.getElementById('path-text').textContent = 'Choose a source node from the graph or node list.';
  document.getElementById('path-banner').classList.add('visible');
  computeVisibility(); markDirty();
}

function handlePathClick(d) {
  if (pathSource && !pathTarget) {
    if (d.id === pathSource) return;
    pathTarget = d.id;
    runPathBFS();
  } else if (pathTarget && !pathSource) {
    if (d.id === pathTarget) return;
    pathSource = d.id;
    runPathBFS();
  } else {
    pathSource = d.id; pathTarget = null; pathResult = null;
    document.getElementById('path-text').textContent =
      'Source: ' + (d.label || d.id) + ' \u2014 click a target node...';
    computeVisibility(); markDirty();
  }
}

function runPathBFS() {
  pathResult = bfsShortestPath(pathSource, pathTarget);
  if (pathResult) {
    const srcLabel = nodeById.get(pathSource)?.label || pathSource;
    const tgtLabel = nodeById.get(pathTarget)?.label || pathTarget;
    document.getElementById('path-text').textContent =
      srcLabel + ' \u2192 ' + tgtLabel + ' (' + pathResult.hops.length +
      ' hop' + (pathResult.hops.length === 1 ? '' : 's') + ')';
    inspectPath(pathResult);
  } else {
    document.getElementById('path-text').textContent = 'No path found \u2014 click a new source...';
    pathSource = null; pathTarget = null; pathResult = null;
  }
  computeVisibility(); markDirty();
}

function exitPathMode() {
  if (!pathMode) return;
  pathMode = false; pathSource = null; pathTarget = null; pathResult = null;
  document.getElementById('btn-path').classList.remove('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'false');
  document.getElementById('path-banner').classList.remove('visible');
  computeVisibility(); markDirty();
}

function enterPathModeFrom(nodeId) {
  exitFocusMode();
  pathMode = true; pathSource = nodeId; pathTarget = null; pathResult = null;
  document.getElementById('btn-path').classList.add('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'true');
  document.getElementById('path-banner').classList.add('visible');
  document.getElementById('path-text').textContent =
    'Source: ' + (nodeById.get(nodeId)?.label || nodeId) + ' \u2014 click a target node...';
  computeVisibility(); markDirty();
}

function enterPathModeTo(nodeId) {
  exitFocusMode();
  pathMode = true; pathSource = null; pathTarget = nodeId; pathResult = null;
  document.getElementById('btn-path').classList.add('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'true');
  document.getElementById('path-banner').classList.add('visible');
  document.getElementById('path-text').textContent =
    'Target: ' + (nodeById.get(nodeId)?.label || nodeId) + ' \u2014 click a source node...';
  computeVisibility(); markDirty();
}

// ── Focus mode ──────────────────────────────────────────────────────────────
function enterFocusMode(nodeId) {
  exitPathMode();
  focusNodeId = nodeId;
  document.getElementById('focus-text').textContent = 'Focused: ' + (nodeById.get(nodeId)?.label || nodeId);
  document.getElementById('focus-banner').classList.add('visible');
  computeVisibility(); markDirty();
}

function exitFocusMode() {
  if (!focusNodeId) return;
  focusNodeId = null;
  document.getElementById('focus-banner').classList.remove('visible');
  computeVisibility(); markDirty();
}

// ── Inspector ───────────────────────────────────────────────────────────────
function inspectNode(d) {
  const panel = document.getElementById('inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  panel.classList.add('open');
  document.getElementById('results-panel').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  title.textContent = d.label || d.id;
  body.textContent = '';

  const m = kindMeta.get(d.kind) || {};
  const badge = el('span', {className: 'kind-badge', textContent: m.label || d.kind});
  badge.style.color = m.color || '#8c99a8';
  badge.style.borderColor = m.color || '#8c99a8';
  body.appendChild(badge);

  // Risk indicator dots
  const riskDiv = el('div', {className: 'risk-indicator'});
  const isInjectable = d.properties?.injectable;
  const hasTier0 = d.properties?.tier === 0;
  const isOwned = d.properties?.owned;
  const vulnLinks = (adjOut.get(d.id) || []).filter(e => e.link.kind === 'rs_AffectedBy');
  const hasKevVuln = vulnLinks.some(({target}) => nodeById.get(target)?.properties?.in_kev);

  const dots = [
    {active: isOwned || hasKevVuln || hasTier0, level: 'critical', title: 'Critical risk'},
    {active: isInjectable || d.properties?.tier === 1, level: 'high', title: 'High risk'},
    {active: vulnLinks.length > 0, level: 'medium', title: 'Medium risk'},
    {active: true, level: 'low', title: 'Baseline'},
  ];
  dots.forEach(({active, level, title: t}) => {
    const dot = el('span', {className: 'risk-dot' + (active ? ' active-' + level : ''), title: t});
    riskDiv.appendChild(dot);
  });
  body.appendChild(riskDiv);

  // Action buttons
  const actions = el('div', {className: 'inspector-actions'});
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Focus Neighbors',
    onclick: () => enterFocusMode(d.id)}));
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Path From',
    onclick: () => enterPathModeFrom(d.id)}));
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Path To',
    onclick: () => enterPathModeTo(d.id)}));
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Center',
    onclick: () => centerOnNode(d)}));
  body.appendChild(actions);

  const props = d.properties || {};
  const skip = new Set(['_icon', '_color']);

  // Split properties into important vs. secondary
  const importantKeys = new Set(['bundle_id', 'name', 'injectable', 'hardened_runtime',
    'library_validation', 'tier', 'owned', 'risk_score', 'cve_id', 'cvss_score',
    'epss_score', 'in_kev', 'sandboxed', 'electron', 'signed_by', 'attack_categories']);
  const entries = Object.entries(props).filter(([k]) => !skip.has(k));
  const importantEntries = entries.filter(([k]) => importantKeys.has(k));
  const secondaryEntries = entries.filter(([k]) => !importantKeys.has(k));

  if (importantEntries.length) {
    const sec = sectionHeader('Key Properties');
    importantEntries.forEach(([k, v]) => {
      const row = propRow(k, v);
      // Highlight dangerous values
      if ((k === 'injectable' && v === true) || (k === 'tier' && v === 0)) row.classList.add('critical-row');
      if (k === 'hardened_runtime' && v === false) row.classList.add('warning-row');
      if (k === 'owned' && v === true) row.classList.add('owned-row');
      sec.appendChild(row);
    });
    body.appendChild(sec);
  }

  if (secondaryEntries.length) {
    const secH = sectionHeader('All Properties');
    const countSpan = el('span', {className: 'section-count', textContent: String(secondaryEntries.length)});
    secH.querySelector('h4').appendChild(countSpan);
    secondaryEntries.forEach(([k, v]) => secH.appendChild(propRow(k, v)));
    body.appendChild(secH);
  }

  // Vulnerability section: show CVE details for Application nodes
  if (vulnLinks.length) {
    const sec = sectionHeader('Vulnerabilities');
    const countSpan = el('span', {className: 'section-count', textContent: String(vulnLinks.length)});
    sec.querySelector('h4').appendChild(countSpan);
    vulnLinks.forEach(({target}) => {
      const vn = nodeById.get(target);
      if (!vn) return;
      const vp = vn.properties || {};
      const cvss = vp.cvss_score != null ? String(vp.cvss_score) : '?';
      const epss = vp.epss_score != null ? Number(vp.epss_score).toFixed(2) : '\u2014';
      const kev = vp.in_kev ? ' KEV' : '';
      const label = (vp.cve_id || '?') + ' (CVSS ' + cvss + ', EPSS ' + epss + ')' + kev;
      const row = propRow(label, vp.title || '');
      if (vp.in_kev) row.classList.add('critical-row');
      else if (vp.epss_score > 0.5) row.classList.add('warning-row');
      else row.classList.add('info-row');
      sec.appendChild(row);
    });
    body.appendChild(sec);
  }

  const outgoing = adjOut.get(d.id) || [];
  const incoming = adjIn.get(d.id) || [];

  if (outgoing.length) {
    const sec = sectionHeader('Outgoing Edges');
    const countSpan = el('span', {className: 'section-count', textContent: String(outgoing.length)});
    sec.querySelector('h4').appendChild(countSpan);
    outgoing.slice(0, 25).forEach(({target, link}) => {
      const tgt = nodeById.get(target);
      const label = edgeKinds.get(link.kind)?.label || link.kind;
      const row = propRow(label, tgt?.label || '?');
      if (link.properties?._traversable) row.classList.add('info-row');
      sec.appendChild(row);
    });
    if (outgoing.length > 25) sec.appendChild(propRow('\u2026', '+' + (outgoing.length - 25) + ' more'));
    body.appendChild(sec);
  }

  if (incoming.length) {
    const sec = sectionHeader('Incoming Edges');
    const countSpan = el('span', {className: 'section-count', textContent: String(incoming.length)});
    sec.querySelector('h4').appendChild(countSpan);
    incoming.slice(0, 25).forEach(({source, link}) => {
      const src = nodeById.get(source);
      const label = edgeKinds.get(link.kind)?.label || link.kind;
      const row = propRow(label, src?.label || '?');
      if (link.properties?._traversable) row.classList.add('info-row');
      sec.appendChild(row);
    });
    if (incoming.length > 25) sec.appendChild(propRow('\u2026', '+' + (incoming.length - 25) + ' more'));
    body.appendChild(sec);
  }
}

function inspectPath(result) {
  const panel = document.getElementById('inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  panel.classList.add('open');
  document.getElementById('results-panel').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  title.textContent = 'Attack Path';
  body.textContent = '';

  // Path summary badge
  const summaryBadge = el('span', {className: 'kind-badge',
    textContent: result.hops.length + ' hop' + (result.hops.length > 1 ? 's' : '')});
  summaryBadge.classList.add('critical-badge');
  body.appendChild(summaryBadge);

  const sec = sectionHeader('Attack Chain');
  result.hops.forEach((hop, i) => {
    const fromNode = nodeById.get(hop.from);
    const toNode = nodeById.get(hop.to);
    const edgeLabel = edgeKinds.get(hop.edge.kind)?.label || hop.edge.kind;
    const row = propRow(
      (i + 1) + '. ' + (fromNode?.label || hop.from),
      edgeLabel + ' \u2192 ' + (toNode?.label || hop.to)
    );
    row.classList.add('critical-row');
    row.setAttribute('tabindex', '0');
    const activate = () => {
      const n = fromNode || toNode;
      if (n) { centerOnNode(n); selectedNode = n; inspectNode(n); markDirty(); }
    };
    row.addEventListener('click', activate);
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); }
    });
    sec.appendChild(row);
  });
  body.appendChild(sec);
}

function closeInspector() {
  document.getElementById('inspector').classList.remove('open');
  document.getElementById('detail-empty').hidden = document.getElementById('results-panel').classList.contains('open');
}

// ── Context menu ────────────────────────────────────────────────────────────
function showContextMenu(event, d) {
  event.preventDefault(); event.stopPropagation();
  const menu = document.getElementById('context-menu');
  menu.textContent = '';

  function ctxItem(icon, text, handler) {
    const item = el('button', {type: 'button', role: 'menuitem', className: 'ctx-item', onclick: handler});
    item.appendChild(el('span', {className: 'ctx-icon', textContent: icon}));
    item.appendChild(el('span', {textContent: text}));
    return item;
  }
  menu.appendChild(ctxItem('\u2192', 'Find paths FROM this node',
    () => { hideContextMenu(); enterPathModeFrom(d.id); }));
  menu.appendChild(ctxItem('\u2190', 'Find paths TO this node',
    () => { hideContextMenu(); enterPathModeTo(d.id); }));
  menu.appendChild(el('div', {className: 'ctx-separator'}));
  menu.appendChild(ctxItem('\u25ce', 'Show neighbors only',
    () => { hideContextMenu(); enterFocusMode(d.id); }));
  menu.appendChild(ctxItem('\u2316', 'Center on this node',
    () => { hideContextMenu(); centerOnNode(d); }));
  menu.appendChild(el('div', {className: 'ctx-separator'}));

  const ownedLabel = d.properties?.owned ? 'Unmark as owned' : 'Mark as owned';
  const ownedIcon = d.properties?.owned ? '\u2610' : '\u2611';
  menu.appendChild(ctxItem(ownedIcon, ownedLabel,
    () => { hideContextMenu(); toggleOwned(d); }));

  const tierHeader = el('div', {className: 'ctx-item'});
  tierHeader.appendChild(el('span', {className: 'ctx-icon', textContent: '\u25b3'}));
  tierHeader.appendChild(el('span', {textContent: 'Set tier', style: 'color:#8b949e'}));
  tierHeader.style.cursor = 'default';
  menu.appendChild(tierHeader);
  ['T0', 'T1', 'T2', 'Clear'].forEach(t => {
    menu.appendChild(el('button', {type: 'button', role: 'menuitem', className: 'ctx-sub', textContent: t,
      onclick: () => { hideContextMenu(); setTier(d, t === 'Clear' ? null : parseInt(t[1])); }}));
  });

  const rect = container.getBoundingClientRect();
  menu.style.left = (event.clientX - rect.left) + 'px';
  menu.style.top = (event.clientY - rect.top) + 'px';
  menu.style.display = 'block';
}

function hideContextMenu() { document.getElementById('context-menu').style.display = 'none'; }
document.addEventListener('click', hideContextMenu);

function centerOnNode(d) {
  transform = {
    x: W / 2 - d.x * 1.5,
    y: H / 2 - d.y * 1.5,
    k: 1.5
  };
  markDirty();
}

function toggleOwned(d) {
  if (!d.properties) d.properties = {};
  d.properties.owned = !d.properties.owned;
  markDirty();
}

function setTier(d, tier) {
  if (!d.properties) d.properties = {};
  d.properties.tier = tier;
  markDirty();
}

// ── Controls ────────────────────────────────────────────────────────────────
function resetZoom() {
  // Fit all visible nodes
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  nodes.forEach(n => {
    if (!visibleNodeIds.has(n.id)) return;
    minX = Math.min(minX, n.x);
    minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x);
    maxY = Math.max(maxY, n.y);
  });
  if (!isFinite(minX)) { transform = {x: 0, y: 0, k: 1}; markDirty(); return; }
  const pad = 80;
  const gw = maxX - minX + pad * 2;
  const gh = maxY - minY + pad * 2;
  const k = Math.min(W / gw, H / gh, 2);
  transform = {
    x: W / 2 - (minX + maxX) / 2 * k,
    y: H / 2 - (minY + maxY) / 2 * k,
    k: k
  };
  markDirty();
}

function toggleLabels() {
  showLabels = !showLabels;
  document.getElementById('btn-labels').classList.toggle('active', showLabels);
  document.getElementById('btn-labels').setAttribute('aria-pressed', String(showLabels));
  markDirty();
}

function toggleAttackPaths() {
  attackPathMode = !attackPathMode;
  document.getElementById('btn-attack').classList.toggle('active', attackPathMode);
  document.getElementById('btn-attack').setAttribute('aria-pressed', String(attackPathMode));
  computeVisibility(); markDirty();
}

function toggleClustering() {
  clusterByType = !clusterByType;
  document.getElementById('btn-cluster').classList.toggle('active', clusterByType);
  document.getElementById('btn-cluster').setAttribute('aria-pressed', String(clusterByType));

  if (clusterByType) {
    const kinds = [...kindMeta.keys()];
    const r = 600;
    kinds.forEach((kind, ki) => {
      const angle = 2 * Math.PI * ki / kinds.length;
      const cx = 1000 + Math.cos(angle) * r;
      const cy = 1000 + Math.sin(angle) * r;
      nodes.forEach((n, j) => {
        if (n.kind === kind) {
          const a2 = 2 * Math.PI * j / nodes.length;
          n.x = cx + Math.cos(a2) * 80 + (Math.random() - 0.5) * 40;
          n.y = cy + Math.sin(a2) * 80 + (Math.random() - 0.5) * 40;
        }
      });
    });
  }
  spatialIndex = new SpatialGrid(nodes);
  // Re-fit view
  resetZoom();
}

let vulnFilterActive = false;
function toggleVulnFilter() {
  vulnFilterActive = !vulnFilterActive;
  document.getElementById('btn-vuln').classList.toggle('active', vulnFilterActive);
  document.getElementById('btn-vuln').setAttribute('aria-pressed', String(vulnFilterActive));
  if (vulnFilterActive) {
    // Show only nodes that have AFFECTED_BY edges (or are Vulnerability nodes)
    const vulnNodeIds = new Set();
    links.forEach(l => {
      if (l.kind === 'rs_AffectedBy') {
        vulnNodeIds.add(l.source);
        vulnNodeIds.add(l.target);
      }
    });
    visibleNodeIds.clear();
    vulnNodeIds.forEach(id => visibleNodeIds.add(id));
    // Also show edges between visible nodes
    visibleLinkSet.clear();
    links.forEach((l, i) => {
      if (visibleNodeIds.has(l.source) && visibleNodeIds.has(l.target)) visibleLinkSet.add(i);
    });
  } else {
    computeVisibility();
  }
  updateAccessibleNodeList();
  markDirty();
}

function exportPNG() {
  const exportCanvas = document.createElement('canvas');
  const scale = 2;
  exportCanvas.width = W * scale;
  exportCanvas.height = H * scale;
  const ectx = exportCanvas.getContext('2d');
  ectx.fillStyle = '#0d1117';
  ectx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);

  // Draw at current transform
  ectx.translate(transform.x * scale, transform.y * scale);
  ectx.scale(transform.k * scale, transform.k * scale);

  // Draw edges
  links.forEach((l, i) => {
    if (!visibleLinkSet.has(i)) return;
    const src = nodeById.get(l.source);
    const tgt = nodeById.get(l.target);
    if (!src || !tgt) return;
    const trav = l.properties?._traversable;
    ectx.beginPath();
    ectx.moveTo(src.x, src.y);
    ectx.lineTo(tgt.x, tgt.y);
    ectx.strokeStyle = trav ? '#58a6ff' : '#30363d';
    ectx.globalAlpha = trav ? 0.5 : 0.2;
    ectx.lineWidth = trav ? 1.5 : 0.7;
    ectx.stroke();
  });

  ectx.globalAlpha = 1;

  // Draw nodes with shapes
  nodes.forEach(n => {
    if (!visibleNodeIds.has(n.id)) return;
    const r = nodeRadius(n);
    const color = n.properties?._color || kindMeta.get(n.kind)?.color || '#8b949e';
    const shape = getNodeShape(n.kind);
    ectx.beginPath();
    drawNodeShape(ectx, n.x, n.y, r, shape);
    ectx.fillStyle = color;
    ectx.fill();
    ectx.strokeStyle = '#21262d';
    ectx.lineWidth = 1.5;
    ectx.stroke();
    if (n.label) {
      ectx.font = '500 10px -apple-system, sans-serif';
      ectx.textAlign = 'center';
      ectx.textBaseline = 'top';
      ectx.fillStyle = '#c9d1d9';
      ectx.fillText(n.label.length > 24 ? n.label.slice(0, 23) + '\u2026' : n.label, n.x, n.y + r + 4);
    }
  });

  // Watermark
  ectx.setTransform(scale, 0, 0, scale, 0, 0);
  ectx.globalAlpha = 0.3;
  ectx.font = '500 11px -apple-system, sans-serif';
  ectx.textAlign = 'right';
  ectx.fillStyle = '#8b949e';
  ectx.fillText('Rootstock Attack Graph', W - 16, H - 12);
  ectx.globalAlpha = 1;

  exportCanvas.toBlob(blob => {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'rootstock-graph.png'; a.click();
    URL.revokeObjectURL(url);
  }, 'image/png');
}

// ── Keyboard shortcuts ──────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  const isInput = document.activeElement?.tagName === 'INPUT' || document.activeElement?.tagName === 'TEXTAREA';

  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    e.preventDefault();
    document.getElementById('search').focus();
    return;
  }

  if (e.key === 'Escape') {
    if (pathMode) { exitPathMode(); return; }
    if (focusNodeId) { exitFocusMode(); return; }
    if (document.getElementById('inspector').classList.contains('open')) { closeInspector(); return; }
    if (searchTerm) {
      document.getElementById('search').value = '';
      searchTerm = '';
      computeVisibility(); markDirty();
      return;
    }
    if (isInput) document.activeElement.blur();
    return;
  }

  if (isInput) return;

  if (e.key === 'p') { togglePathMode(); return; }
  if (e.key === 'a') { toggleAttackPaths(); return; }
  if (e.key === 'l') { toggleLabels(); return; }
  if (e.key === 'r') { resetZoom(); return; }

  const num = parseInt(e.key);
  if (num >= 1 && num <= 9) {
    const kinds = [...kindMeta.keys()].sort((a, b) => kindMeta.get(b).count - kindMeta.get(a).count);
    if (num <= kinds.length) {
      const kind = kinds[num - 1];
      const cb = document.querySelector('#node-filters input[data-kind="' + kind + '"]');
      if (cb) {
        cb.checked = !cb.checked;
        if (cb.checked) activeNodeKinds.add(kind);
        else activeNodeKinds.delete(kind);
        computeVisibility(); markDirty();
      }
    }
  }
});

// ── Initial setup ───────────────────────────────────────────────────────────
computeVisibility();
// Fit to visible nodes on load
setTimeout(resetZoom, 50);

// Stats - build a rich stats bar
const statsEl = document.getElementById('stats');

function addStatItem(color, text) {
  const item = el('span', {className: 'stat-item'});
  if (color) {
    const dot = el('span', {className: 'stat-dot'});
    dot.style.background = color;
    item.appendChild(dot);
  }
  item.appendChild(el('span', {textContent: text}));
  statsEl.appendChild(item);
}

function updateStats() {
  const attackEdgeCount = [...edgeKinds.values()].filter(e => e.traversable).reduce((s,e) => s + e.count, 0);
  const ownedCount = nodes.filter(n => n.properties?.owned).length;
  const criticalNodes = nodes.filter(n => n.properties?.risk_level === 'critical').length;
  const highRiskNodes = nodes.filter(n => n.properties?.risk_level === 'high').length;
  const tier0Count = nodes.filter(n => n.properties?.tier === 0).length;
  const injectableCount = nodes.filter(n => n.properties?.injectable).length;

  statsEl.textContent = '';
  addStatItem('#8b949e', nodes.length + ' nodes');
  addStatItem('#30363d', links.length + ' edges');
  addStatItem('#58a6ff', attackEdgeCount + ' attack');
  if (criticalNodes > 0) addStatItem('#f85149', criticalNodes + ' critical');
  if (highRiskNodes > 0) addStatItem('#d29922', highRiskNodes + ' high');
  if (tier0Count > 0) addStatItem('#f85149', tier0Count + ' T0');
  if (injectableCount > 0) addStatItem('#ff7b72', injectableCount + ' injectable');
  if (ownedCount > 0) addStatItem('#ffd700', ownedCount + ' owned');
}
updateStats();

// ── Risk posture summary chips ────────────────────────────────────────────
const riskSummaryEl = document.getElementById('risk-summary');
function addRiskChip(level, count) {
  if (count === 0) return;
  const chip = el('span', {className: 'risk-chip ' + level});
  chip.appendChild(el('span', {className: 'chip-count', textContent: String(count)}));
  chip.appendChild(el('span', {textContent: level.charAt(0).toUpperCase() + level.slice(1)}));
  riskSummaryEl.appendChild(chip);
}

function updateRiskSummary() {
  const criticalNodes = nodes.filter(n => n.properties?.risk_level === 'critical').length;
  const highRiskNodes = nodes.filter(n => n.properties?.risk_level === 'high').length;
  const mediumNodes = nodes.filter(n => n.properties?.risk_level === 'medium').length;
  const lowNodes = nodes.filter(n => n.properties?.risk_level === 'low').length;
  riskSummaryEl.textContent = '';
  addRiskChip('critical', criticalNodes);
  addRiskChip('high', highRiskNodes);
  addRiskChip('medium', mediumNodes);
  addRiskChip('low', lowNodes);
  // If no risk data, show a placeholder
  if (criticalNodes + highRiskNodes + mediumNodes + lowNodes === 0) {
    riskSummaryEl.appendChild(el('span', {textContent: 'No risk scores computed',
      className: 'risk-chip'}));
  }
}
updateRiskSummary();

// ── Live API integration ─────────────────────────────────────────────────
const isLive = typeof __ROOTSTOCK_LIVE__ !== 'undefined';
const API_TOKEN_KEY = '__rootstock_api_token__';

function getApiToken() {
  return sessionStorage.getItem(API_TOKEN_KEY) || '';
}

function showConnectionGate(message = '') {
  if (!isLive) return;
  const gate = document.getElementById('connection-gate');
  const error = document.getElementById('connection-error');
  gate.hidden = false;
  error.textContent = message;
  error.hidden = !message;
  const status = document.getElementById('connection-status');
  status.textContent = message ? 'Connection required' : 'Not connected';
  status.className = 'status-chip' + (message ? ' error' : '');
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(() => document.getElementById('api-token').focus());
  }
}

function hideConnectionGate() {
  document.getElementById('connection-gate').hidden = true;
  const status = document.getElementById('connection-status');
  status.textContent = 'Live · connected';
  status.className = 'status-chip connected';
}

function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = getApiToken();
  if (token) headers.set('Authorization', 'Bearer ' + token);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  return fetch(API_BASE + path, {...options, headers, signal: options.signal || controller.signal}).then(async response => {
    if (response.status === 401) {
      sessionStorage.removeItem(API_TOKEN_KEY);
      showConnectionGate('Session expired or token rejected. Enter the current API token.');
    }
    if (response.ok) {
      return response;
    }
    let detail = '';
    try {
      const text = await response.text();
      if (text) {
        try {
          const payload = JSON.parse(text);
          if (typeof payload.detail === 'string') {
            detail = payload.detail;
          } else if (payload.detail) {
            detail = JSON.stringify(payload.detail);
          } else {
            detail = text;
          }
        } catch (_err) {
          detail = text;
        }
      }
    } catch (_err) {
      detail = '';
    }
    if (response.status === 401) {
      throw new Error('Unauthorized');
    }
    const status = 'HTTP ' + response.status + (response.statusText ? ' ' + response.statusText : '');
    throw new Error(detail ? status + ': ' + detail : status);
  }).catch(error => {
    if (error?.name === 'AbortError') throw new Error('Request timed out after 15 seconds');
    throw error;
  }).finally(() => clearTimeout(timeoutId));
}

function loadLiveQueries() {
  const list = document.getElementById('query-list');
  list.textContent = '';
  list.appendChild(el('p', {className: 'empty-state', textContent: 'Loading saved queries…'}));
  return apiFetch('/api/queries')
    .then(r => r.json())
    .then(queries => {
      if (!Array.isArray(queries)) throw new Error('Malformed query-list response');
      list.textContent = '';
      const grouped = {
        'Red Team': queries.filter(q => q.category === 'Red Team'),
        'Blue Team': queries.filter(q => q.category === 'Blue Team'),
        'Forensic': queries.filter(q => q.category === 'Forensic'),
      };
      Object.entries(grouped).forEach(([cat, qs]) => {
        qs.forEach(q => {
          const sevClass = String(q.severity || '').toLowerCase();
          const item = el('button', {type: 'button', className: 'query-item', onclick: () => runLiveQuery(q)}, [
            el('span', {className: 'severity-dot ' + sevClass, 'aria-hidden': 'true'}),
            el('span', {className: 'query-name', textContent: '[' + q.id + '] ' + q.name}),
            el('span', {className: 'cat-badge', textContent: cat.split(' ')[0]}),
          ]);
          item.title = q.purpose || q.name;
          list.appendChild(item);
        });
      });
      if (!queries.length) list.appendChild(el('p', {className: 'empty-state', textContent: 'No saved queries are available.'}));
    })
    .catch(err => {
      list.textContent = '';
      list.appendChild(el('p', {className: 'empty-state', textContent: 'Saved queries failed to load: ' + err.message}));
      setLiveStatus('Saved queries failed to load: ' + err.message, 'error');
    });
}

function startLiveSession() {
  hideConnectionGate();
  loadLiveQueries();
  liveRefresh();
}

if (isLive) {
  document.getElementById('query-section').classList.add('live');
  document.getElementById('live-actions').classList.add('live');
  document.getElementById('custom-query-section').hidden = false;
  document.getElementById('connection-status').textContent = 'Not connected';
  if (getApiToken()) startLiveSession();
  else showConnectionGate();
} else {
  document.getElementById('connection-status').textContent = 'Offline · self-contained';
}

function runLiveQuery(q) {
  if (!isLive) return;
  const panel = document.getElementById('results-panel');
  const body = document.getElementById('results-body');
  const meta = document.getElementById('results-meta');
  document.getElementById('results-title').textContent = '[' + q.id + '] ' + q.name;
  meta.textContent = 'Loading...';
  body.textContent = '';
  document.getElementById('inspector').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  panel.classList.add('open');

  apiFetch('/api/queries/' + q.id + '/run', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({params: {}})
  })
    .then(r => r.json())
    .then(data => {
      if (!data || !Array.isArray(data.rows) || typeof data.count !== 'number') {
        throw new Error('Malformed query response');
      }
      meta.textContent = data.count + ' row(s) \u00b7 ' + q.category + ' \u00b7 ' + q.severity;
      if (!data.rows || data.rows.length === 0) {
        body.textContent = '';
        body.appendChild(el('div', {textContent: 'No results.', className: 'prop-row'}));
        if (q.severity === 'Critical' || q.severity === 'High') {
          body.appendChild(el('div', {
            textContent: '\u2713 No findings \u2014 positive security result.',
            className: 'prop-row'
          }));
        }
        return;
      }
      // Build table
      const headers = Object.keys(data.rows[0]);
      const table = document.createElement('table');
      table.appendChild(el('caption', {className: 'sr-only', textContent: 'Results for ' + q.name}));
      const thead = document.createElement('thead');
      const hrow = document.createElement('tr');
      headers.forEach(h => {
        const th = document.createElement('th');
        th.textContent = h;
        hrow.appendChild(th);
      });
      hrow.appendChild(el('th', {textContent: 'Action', scope: 'col'}));
      thead.appendChild(hrow);
      table.appendChild(thead);

      const tbody = document.createElement('tbody');
      data.rows.forEach(row => {
        const tr = document.createElement('tr');
        headers.forEach(h => {
          const td = document.createElement('td');
          const val = row[h];
          td.textContent = Array.isArray(val) ? val.join(', ') : String(val ?? '');
          td.title = td.textContent;
          tr.appendChild(td);
        });
        const actionCell = document.createElement('td');
        actionCell.appendChild(el('button', {type: 'button', textContent: 'Highlight node', onclick: () => highlightQueryResult(row)}));
        tr.appendChild(actionCell);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      body.textContent = '';
      body.appendChild(table);
    })
    .catch(err => {
      meta.textContent = 'Error: ' + err.message;
      body.textContent = '';
      body.appendChild(el('div', {className: 'prop-row'}, [
        el('strong', {textContent: 'Query failed'}),
        el('span', {textContent: err.message})
      ]));
    });
}

function highlightQueryResult(row) {
  // Try to find matching nodes by bundle_id or name
  const bid = row.bundle_id || row.app_bundle_id;
  const name = row.app || row.name || row.attacker || row.victim_user;
  let matchId = null;
  if (bid) {
    for (const n of nodes) {
      if (n.properties?.bundle_id === bid) { matchId = n.id; break; }
    }
  }
  if (!matchId && name) {
    for (const n of nodes) {
      if (n.label === name || n.properties?.name === name) { matchId = n.id; break; }
    }
  }
  if (matchId) {
    const node = nodeById.get(matchId);
    if (node) { centerOnNode(node); selectedNode = node; inspectNode(node); markDirty(); }
  }
}

function closeResults() {
  document.getElementById('results-panel').classList.remove('open');
  document.getElementById('detail-empty').hidden = document.getElementById('inspector').classList.contains('open');
}

function setLiveStatus(message, state = '') {
  const status = document.getElementById('live-status');
  if (!status) return;
  status.textContent = message || '';
  status.className = 'live-status' + (state ? ' ' + state : '');
}

function liveRefresh() {
  if (!isLive) return;
  setLiveStatus('Refreshing graph...', 'pending');
  apiFetch('/api/graph')
    .then(r => r.json())
    .then(data => {
      if (!data || !data.graph || !Array.isArray(data.graph.nodes) || !Array.isArray(data.graph.edges)) {
        throw new Error('Malformed graph response');
      }
      replaceGraphData(data);
      resetZoom();
      setLiveStatus('Graph refreshed.', 'ok');
    })
    .catch(err => {
      setLiveStatus('Graph refresh failed: ' + err.message, 'error');
    });
}

function liveTierClassify() {
  if (!isLive) return;
  setLiveStatus('Classifying tiers...', 'pending');
  apiFetch('/api/tier-classify', {method: 'POST'})
    .then(r => r.json())
    .then(data => {
      if (!data || typeof data.tier0 !== 'number' || typeof data.tier1 !== 'number' ||
          typeof data.tier2 !== 'number' || typeof data.total !== 'number') {
        throw new Error('Malformed tier response');
      }
      if (data.total !== data.tier0 + data.tier1 + data.tier2) {
        throw new Error('Malformed tier response');
      }
      const message = 'Tier classification complete: T0=' + data.tier0 + ' T1=' + data.tier1 + ' T2=' + data.tier2;
      setLiveStatus(message, 'ok');
      alert(message);
      liveRefresh();
    })
    .catch(err => {
      setLiveStatus('Tier classification failed: ' + err.message, 'error');
    });
}

function liveShowOwned() {
  if (!isLive) return;
  setLiveStatus('Loading owned nodes...', 'pending');
  apiFetch('/api/owned')
    .then(r => r.json())
    .then(data => {
      if (!data || !Array.isArray(data.owned) || typeof data.count !== 'number') {
        throw new Error('Malformed owned response');
      }
      if (data.count !== data.owned.length) {
        throw new Error('Malformed owned response');
      }
      if (data.count === 0) {
        setLiveStatus('No owned nodes returned.', 'ok');
        alert('No owned nodes.');
        return;
      }
      // Highlight owned nodes by selecting all matching
      let highlighted = 0;
      data.owned.forEach(item => {
        const name = item.name;
        let matched = false;
        nodes.forEach(n => {
          if (n.properties?.name === name || n.properties?.bundle_id === name) {
            if (!n.properties) n.properties = {};
            n.properties.owned = true;
            matched = true;
          }
        });
        if (matched) highlighted++;
      });
      if (highlighted > 0) markDirty();
      if (highlighted === data.count) {
        setLiveStatus(data.count + ' owned node(s) highlighted.', 'ok');
        alert(data.count + ' owned node(s) highlighted.');
      } else {
        setLiveStatus('Owned list loaded, but only ' + highlighted + ' of ' + data.count + ' matched the current graph.', 'error');
      }
    })
    .catch(err => {
      setLiveStatus('Show owned failed: ' + err.message, 'error');
    });
}

// ── Custom Cypher console ────────────────────────────────────────────────
function runCustomCypher() {
  if (!isLive) return;
  const input = document.getElementById('cypher-input');
  const cypher = input.value.trim();
  if (!cypher) {
    setLiveStatus('Enter a read-only Cypher query before running it.', 'error');
    input.focus();
    return;
  }

  // Save to history (localStorage, last 10)
  const historyKey = 'rootstock.cypherHistory';
  let history = [];
  try { history = JSON.parse(localStorage.getItem(historyKey) || '[]'); } catch(e) {}
  history = [cypher, ...history.filter(h => h !== cypher)].slice(0, 10);
  localStorage.setItem(historyKey, JSON.stringify(history));
  _updateCypherHistory(history);

  const panel = document.getElementById('results-panel');
  const body = document.getElementById('results-body');
  const meta = document.getElementById('results-meta');
  document.getElementById('results-title').textContent = 'Custom Cypher';
  meta.textContent = 'Running...';
  body.textContent = '';
  document.getElementById('inspector').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  panel.classList.add('open');
  const runButton = document.getElementById('run-cypher');
  runButton.disabled = true;
  runButton.textContent = 'Running…';

  apiFetch('/api/cypher', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({cypher: cypher, params: {}})
  })
    .then(r => {
      if (r.status === 403) return r.json().then(d => { throw new Error(d.detail || 'Write operations not allowed'); });
      if (!r.ok) return r.json().then(d => { throw new Error(d.detail || 'Query failed'); });
      return r.json();
    })
    .then(data => {
      meta.textContent = data.count + ' row(s)';
      if (!data.rows || data.rows.length === 0) {
        body.appendChild(el('div', {textContent: 'No results.', className: 'prop-row'}));
        return;
      }
      const headers = data.columns || Object.keys(data.rows[0]);
      const table = document.createElement('table');
      table.appendChild(el('caption', {className: 'sr-only', textContent: 'Custom Cypher results'}));
      const thead = document.createElement('thead');
      const hrow = document.createElement('tr');
      headers.forEach(h => { const th = document.createElement('th'); th.textContent = h; hrow.appendChild(th); });
      hrow.appendChild(el('th', {textContent: 'Action', scope: 'col'}));
      thead.appendChild(hrow);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      data.rows.forEach(row => {
        const tr = document.createElement('tr');
        headers.forEach(h => {
          const td = document.createElement('td');
          const val = row[h];
          td.textContent = Array.isArray(val) ? val.join(', ') : String(val ?? '');
          td.title = td.textContent;
          tr.appendChild(td);
        });
        const actionCell = document.createElement('td');
        actionCell.appendChild(el('button', {type: 'button', textContent: 'Highlight node', onclick: () => highlightQueryResult(row)}));
        tr.appendChild(actionCell);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      body.textContent = '';
      body.appendChild(table);
    })
    .catch(err => {
      meta.textContent = 'Error: ' + err.message;
      body.textContent = '';
      body.appendChild(el('div', {className: 'empty-state', textContent: 'Query failed: ' + err.message}));
    })
    .finally(() => {
      runButton.disabled = false;
      runButton.textContent = 'Run query';
    });
}

function _updateCypherHistory(history) {
  const sel = document.getElementById('cypher-history-select');
  if (!sel) return;
  // Clear existing options safely
  while (sel.options.length > 1) sel.remove(1);
  history.forEach(q => {
    const opt = document.createElement('option');
    opt.value = q;
    opt.textContent = q.length > 40 ? q.substring(0, 40) + '...' : q;
    sel.appendChild(opt);
  });
}

// Load history on startup
try {
  const oldKey = '__rs_cypher_history__';
  if (!localStorage.getItem('rootstock.cypherHistory') && localStorage.getItem(oldKey)) {
    localStorage.setItem('rootstock.cypherHistory', localStorage.getItem(oldKey));
    localStorage.removeItem(oldKey);
  }
  const h = JSON.parse(localStorage.getItem('rootstock.cypherHistory') || '[]');
  if (h.length) _updateCypherHistory(h);
} catch(e) {}

// Allow Ctrl+Enter to run
document.getElementById('cypher-input')?.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runCustomCypher(); }
});

// Override toggleOwned in live mode to persist to API
if (isLive) {
  toggleOwned = function(d) {
    const wasOwned = d.properties?.owned === true;
    const body = {};
    if (d.properties?.bundle_id) body.bundle_ids = [d.properties.bundle_id];
    else if (d.properties?.name && d.kind === 'rs_User') body.usernames = [d.properties.name];
    else {
      setLiveStatus('Owned update failed: node has no supported identifier.', 'error');
      return;
    }

    const path = wasOwned ? '/api/clear-owned' : '/api/mark-owned';
    const countKey = wasOwned ? 'cleared' : 'marked';
    const action = wasOwned ? 'Clear owned' : 'Mark owned';
    setLiveStatus(action + ' pending...', 'pending');
    apiFetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    })
      .then(r => r.json())
      .then(data => {
        if (!data || typeof data[countKey] !== 'number') {
          throw new Error('Malformed owned update response');
        }
        if (data[countKey] <= 0) {
          throw new Error('No matching nodes changed');
        }
        if (!d.properties) d.properties = {};
        d.properties.owned = !wasOwned;
        markDirty();
        if (selectedNode?.id === d.id) inspectNode(d);
        setLiveStatus(action + ' saved for ' + data[countKey] + ' node(s).', 'ok');
      })
      .catch(err => {
        if (!d.properties) d.properties = {};
        d.properties.owned = wasOwned;
        markDirty();
        if (selectedNode?.id === d.id) inspectNode(d);
        setLiveStatus(action + ' failed: ' + err.message, 'error');
      });
  };
}

// Keyboard: Escape closes results panel
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.getElementById('results-panel').classList.contains('open')) {
    closeResults();
    e.stopPropagation();
  }
}, true);

// ── Semantic shell controls ────────────────────────────────────────────────
function selectWorkbenchTab(name) {
  const explore = name === 'explore';
  document.getElementById('tab-explore').setAttribute('aria-selected', String(explore));
  document.getElementById('tab-queries').setAttribute('aria-selected', String(!explore));
  document.getElementById('explore-panel').hidden = !explore;
  document.getElementById('queries-panel').hidden = explore;
  resizeCanvas();
}

document.getElementById('tab-explore').addEventListener('click', () => selectWorkbenchTab('explore'));
document.getElementById('tab-queries').addEventListener('click', () => selectWorkbenchTab('queries'));
document.querySelector('[role="tablist"]').addEventListener('keydown', event => {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  const next = event.key === 'ArrowRight' ? document.getElementById('tab-queries') : document.getElementById('tab-explore');
  selectWorkbenchTab(next.id === 'tab-queries' ? 'queries' : 'explore');
  next.focus();
});

document.getElementById('clear-search').addEventListener('click', () => {
  const search = document.getElementById('search');
  search.value = '';
  searchTerm = '';
  computeVisibility();
  markDirty();
  search.focus();
});

document.getElementById('clear-filters').addEventListener('click', () => {
  activeNodeKinds.clear();
  kindMeta.forEach((_info, kind) => activeNodeKinds.add(kind));
  activeEdgeKinds.clear();
  edgeKinds.forEach((_info, kind) => activeEdgeKinds.add(kind));
  searchTerm = '';
  document.getElementById('search').value = '';
  buildFilters();
  computeVisibility();
  markDirty();
});

const themeSelect = document.getElementById('theme-select');
const savedTheme = localStorage.getItem('rootstock.theme') || 'system';
themeSelect.value = ['system', 'light', 'dark'].includes(savedTheme) ? savedTheme : 'system';
function applyTheme(value) {
  if (value === 'system') {
    document.documentElement.removeAttribute('data-theme');
    document.body.removeAttribute('data-theme');
  } else {
    document.documentElement.setAttribute('data-theme', value);
    document.body.setAttribute('data-theme', value);
  }
  localStorage.setItem('rootstock.theme', value);
  markDirty();
}
applyTheme(themeSelect.value);
themeSelect.addEventListener('change', event => applyTheme(event.target.value));

document.getElementById('btn-reset').addEventListener('click', resetZoom);
document.getElementById('btn-labels').addEventListener('click', toggleLabels);
document.getElementById('btn-cluster').addEventListener('click', toggleClustering);
document.getElementById('btn-attack').addEventListener('click', toggleAttackPaths);
document.getElementById('btn-path').addEventListener('click', togglePathMode);
document.getElementById('btn-vuln').addEventListener('click', toggleVulnFilter);
document.getElementById('btn-export').addEventListener('click', exportPNG);
document.getElementById('focus-exit').addEventListener('click', exitFocusMode);
document.getElementById('path-exit').addEventListener('click', exitPathMode);
document.getElementById('inspector-close').addEventListener('click', closeInspector);
document.getElementById('results-close').addEventListener('click', closeResults);
document.getElementById('run-cypher').addEventListener('click', runCustomCypher);
document.getElementById('live-refresh').addEventListener('click', liveRefresh);
document.getElementById('live-tier').addEventListener('click', liveTierClassify);
document.getElementById('live-owned').addEventListener('click', liveShowOwned);
document.getElementById('cypher-history-select').addEventListener('change', event => {
  if (event.target.value) document.getElementById('cypher-input').value = event.target.value;
});
document.getElementById('clear-history').addEventListener('click', () => {
  localStorage.removeItem('rootstock.cypherHistory');
  _updateCypherHistory([]);
  setLiveStatus('Local Cypher history cleared.', 'ok');
});

document.getElementById('connection-form').addEventListener('submit', event => {
  event.preventDefault();
  const input = document.getElementById('api-token');
  const token = input.value.trim();
  if (!token) return;
  sessionStorage.setItem(API_TOKEN_KEY, token);
  input.value = '';
  startLiveSession();
});
