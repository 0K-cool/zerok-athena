# 0K SaaS Dashboard Template

**Version:** v2.0
**Updated:** February 4, 2026

Reusable security dashboard template for **0K family projects** (Talon, ATHENA, Vex, and future products).

## Design System

**Base:** Charcoal (#222222) - This template is NOT for blue-based products like DetectIQ.

### Themes (Layout)

| Theme | Description |
|-------|-------------|
| `default` | Dark backdrop behind widgets, top bar visible |
| `minimal` | Uniform charcoal background, bordered widgets, no top bar |

### Accent Colors

| Accent | Hex | Use Case |
|--------|-----|----------|
| `orange` | #c2703c | 0K default |
| `red` | #dc2626 | ATHENA (pentest) |
| `blue` | #3b82f6 | General |
| `green` | #22c55e | General |
| `purple` | #8b5cf6 | General |

## Usage

### HTML Setup

```html
<!-- 0K Default (orange accent) -->
<html data-theme="default" data-accent="orange">

<!-- ATHENA with Minimal layout -->
<html data-theme="minimal" data-accent="red">

<!-- Mix and match -->
<html data-theme="minimal" data-accent="purple">
```

### CSS Variables

All variables use the `--zerok-` prefix:

```css
var(--zerok-primary)      /* Accent color */
var(--zerok-bg)           /* Background */
var(--zerok-sidebar)      /* Sidebar background */
var(--zerok-card)         /* Widget/card background */
var(--zerok-text)         /* Primary text */
var(--zerok-text-muted)   /* Secondary text */
var(--zerok-border)       /* Border color */
```

### LocalStorage

Preferences persist automatically:
- `zerok-theme` - Layout theme (default/minimal)
- `zerok-accent` - Accent color (orange/red/blue/green/purple)

## Adding New Widgets

**Spacing Convention (IMPORTANT):**

All widget container rows MUST use consistent spacing:
- `gap: 6px` - between widgets horizontally
- `margin-bottom: 6px` - between rows vertically

```css
/* 3-column row */
.widget-grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 6px;
  margin-bottom: 6px;
}

/* 2-column row */
.two-columns {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  margin-bottom: 6px;
}
```

When adding new widget rows, always include both `gap` and `margin-bottom` properties.

## Customizing Branding

Update the sidebar brand for your project:

```html
<span class="sidebar-title">
  <span class="brand-0k"><span class="slashed-zero">0</span>K</span>
  <span class="brand-name">YourProject</span>  <!-- Change this -->
</span>
```

## Architecture Decisions

### ADR-001: Charcoal Base Only

**DetectIQ** (and other blue-based products) should have their own separate template with blue backgrounds baked in. This template stays focused on the charcoal-based 0K visual identity.

*Decision made: February 3, 2026*

---

### ADR-002: Fixed Layout (No Drag-and-Drop)

**Decision:** This template uses a fixed CSS Grid layout. Widgets cannot be dragged, resized, or rearranged by end users.

**Context:** Modern dashboards like Grafana and Datadog offer drag-and-drop widget customization using libraries like [React Grid Layout](https://github.com/react-grid-layout/react-grid-layout) or [Gridstack.js](https://gridstackjs.com/).

**Rationale:**

| Factor | Fixed Layout (Chosen) | Drag-and-Drop |
|--------|----------------------|---------------|
| Complexity | Low - pure CSS | High - JS state management |
| Dependencies | None | Gridstack.js or React Grid Layout |
| Mobile responsive | Easy | Harder to maintain |
| State persistence | Not needed | localStorage/backend required |
| Security dashboards | Better - consistent muscle memory | Users may hide critical alerts |
| Target user | Developers customizing template | End users building custom views |

**When to reconsider:**
- End users explicitly request layout customization
- Building a true analytics/BI platform where users have wildly different workflows
- A specific product (Talon, ATHENA) has validated user demand

**Alternatives considered:**
1. **Gridstack.js** - Framework-agnostic, good for vanilla JS. Rejected: adds complexity without clear user demand.
2. **React Grid Layout** - Best for React apps. Rejected: template is vanilla HTML/CSS.
3. **Widget visibility toggle** - Simple show/hide without drag. Could add later as middle ground.

**Migration path:** The current CSS Grid structure (`.widget-grid`, `.two-columns`) can be replaced with Gridstack.js later if needed. No structural changes required.

*Decision made: February 3, 2026*

## File Structure

```
zerok-dashboard/
├── index.html      # Full dashboard template
├── README.md       # This file
└── .gitignore
```

## Preview

Open `index.html` in a browser to preview the dashboard.

---

## Version History

### v2.0 (February 4, 2026)
- Synced from vex-talon security dashboard
- GitHub-inspired dark theme
- 20-layer defense-in-depth grid visualization
- Framework coverage matrices:
  - OWASP LLM Top 10 2025
  - OWASP Agentic Top 10 2026
  - MITRE ATLAS technique coverage
- Collapsible sidebar with accent bar navigation
- Event timeline with severity filtering
- Statistics cards (CRITICAL/HIGH/MEDIUM/LOW)
- Responsive design improvements

### v1 Alpha (February 3, 2026)
- Initial template release
- Two layout themes: Default, Minimal
- Five accent colors: Orange, Red, Blue, Green, Purple
- Sidebar with collapsible sections
- User profile section
- Stat cards, widget grid, event lists
- Theme/accent persistence via localStorage
- CSS variables with `--zerok-*` prefix
- Chart.js integration with dynamic accent colors
- Documented spacing convention for widget rows

## Roadmap (Future)

Improvements to add as real projects reveal gaps:

- [ ] Responsive/mobile breakpoints
- [ ] Additional widget types (tables, forms, modals)
- [ ] Loading/skeleton states
- [ ] Toast notification system
- [ ] Extract to separate CSS/JS files
- [ ] Accessibility improvements (ARIA, keyboard nav)
