# Viewer Performance Redesign — Canvas + Progressive Disclosure

**Date:** 2026-03-20
**Status:** Implemented

## Problem

The original viewer rendered all 2,374 nodes and 4,880 edges as SVG DOM elements with a live D3 force simulation. This created ~12,000 SVG elements repositioned every physics tick, causing ~5fps on a MacBook Air M4.

## Solution

Replaced SVG rendering with HTML5 Canvas and added progressive disclosure so users see a useful, fast view immediately and expand on demand.

## Architecture

### 1. Pre-computed Layout (Python — viewer.py)

The force-directed layout runs in Python using a simple iterative force algorithm before generating the HTML. The browser receives x,y positions for every node — zero physics delay on load.

- Iterative spring/charge model with grid-based approximation for large graphs
- Nodes initially clustered by kind for visual grouping
- Positions stored in the JSON data blob alongside node properties
- ~2,400 nodes converges in <2s in Python

### 2. Canvas Renderer (JavaScript)

Replaced D3 SVG rendering with a Canvas 2D context:

- Single `<canvas>` element, no DOM nodes for graph elements
- Draw loop: `requestAnimationFrame` only redraws on dirty flag (pan, zoom, filter, hover)
- Hit-testing via quadtree for click/hover detection
- Viewport culling: only nodes/edges within view are drawn
- Edges drawn as lines with arrow markers
- Nodes drawn as filled circles with optional labels

### 3. Progressive Disclosure (Default View)

On load, only **Application** nodes are visible (184 out of 2,374). All edge types are enabled. Sidebar checkboxes (unchecked by default for non-Application types) let users reveal:

- Entitlements (949 nodes)
- XPC Services (439)
- Launch Items (439)
- Keychain Items (168)
- Certificate Authorities (73)
- All other types

### 4. Semantic Zoom

- **Zoom < 0.2:** Nodes are dots, no labels.
- **Zoom 0.2–0.4:** Labels appear only for high-degree nodes (degree > 5).
- **Zoom > 0.4:** All visible node labels rendered.
- Only nodes within the viewport are label-rendered (viewport culling).
- Hovered/selected/path-endpoint nodes always show labels regardless of zoom.

### 5. Interaction Model

- **Hover** over a node: temporary neighbor highlight (preview)
- **Click** a node: pins the neighbor highlight persistently (stays during pan/zoom)
- **Click** same node again: unpins
- **Click** different node: re-pins to new node
- **Click** empty space: unpins all
- **Pan/drag** detection: mouse movement > 4px suppresses the click event, so panning never accidentally unpins

### 6. Preserved Features

All original features maintained with Canvas equivalents:

- Sidebar filters (node type checkboxes, edge type toggles)
- Search by name/bundle_id (highlights matches)
- Click-to-inspect panel (node and edge properties)
- Path mode (BFS shortest path with highlighting)
- Focus mode (1-hop neighborhood)
- Attack path toggle
- Owned node highlighting (gold glow)
- Tier badges on nodes
- Context menu (right-click)
- Keyboard shortcuts (p=path, a=attack, l=labels, r=reset, 1-9=toggle types)
- PNG export (native canvas `toBlob`)
- Drag to reposition nodes
- Zoom/pan (scroll wheel + click-drag)

## Files Changed

- `graph/viewer.py` — Full rewrite: Canvas renderer, pre-computed layout, progressive disclosure, click-to-pin interaction
- `graph/infer_file_acl.py` — Split compound Cypher query for Neo4j 5 compatibility (unrelated bugfix during testing)

## Performance Results

| Metric | Before (SVG) | After (Canvas) |
|--------|--------------|----------------|
| Initial render | ~5fps, 3-5s stutter | <100ms, 60fps |
| Full graph (2,374 nodes) | Unusable | 60fps pan/zoom |
| Default view (184 apps) | N/A (showed everything) | Instant, focused |
| Search/filter | 200-500ms lag | <50ms |
