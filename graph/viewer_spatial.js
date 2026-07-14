/* global module, nodeRadius, nodes, visibleNodeIds */
/* exported spatialIndex */

// ── Spatial grid for bounded hit-testing ────────────────────────────────────
class SpatialGrid {
  constructor(nodes, options = {}) {
    this.cellSize = 64;
    this.cells = new Map();
    this.isVisible = options.isVisible || (node => visibleNodeIds.has(node.id));
    this.radiusFor = options.radiusFor || nodeRadius;
    nodes.forEach(node => {
      const key = this.key(node.x, node.y);
      if (!this.cells.has(key)) this.cells.set(key, []);
      this.cells.get(key).push(node);
    });
  }

  key(x, y) {
    return Math.floor(x / this.cellSize) + ':' + Math.floor(y / this.cellSize);
  }

  candidatesNear(px, py, maxDist) {
    const radius = Math.ceil((maxDist + 24) / this.cellSize);
    const cx = Math.floor(px / this.cellSize);
    const cy = Math.floor(py / this.cellSize);
    const candidates = [];
    for (let x = cx - radius; x <= cx + radius; x++) {
      for (let y = cy - radius; y <= cy + radius; y++) {
        candidates.push(...(this.cells.get(x + ':' + y) || []));
      }
    }
    return candidates;
  }

  distanceFromNode(node, px, py, maxDist) {
    if (!this.isVisible(node)) return null;
    const dx = node.x - px;
    const dy = node.y - py;
    const radius = this.radiusFor(node);
    const centerDistance = Math.hypot(dx, dy);
    if (centerDistance > radius + maxDist) return null;
    // A point inside a node is equally close to its clickable area.  This
    // keeps node selection geometric instead of preferring an arbitrary
    // center when clickable regions overlap.
    return Math.max(0, centerDistance - radius);
  }

  findNearest(px, py, maxDist) {
    let best = null;
    let bestDistance = Infinity;
    for (const node of this.candidatesNear(px, py, maxDist)) {
      const distance = this.distanceFromNode(node, px, py, maxDist);
      if (distance === null) continue;
      if (distance < bestDistance ||
          (distance === bestDistance && best && String(node.id) < String(best.id))) {
        bestDistance = distance;
        best = node;
      }
    }
    return best;
  }
}

if (typeof module !== 'undefined') module.exports = {SpatialGrid};

let spatialIndex = typeof document === 'undefined' ? null : new SpatialGrid(nodes);
