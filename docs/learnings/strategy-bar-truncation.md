# Strategy Bar Truncation — Preamble Wastes Limited Space

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** LOW — cosmetic

## Problem

ST synthesizes strategy summaries for the bar, but the first line is often a generic preamble like "Strategy posted. Here's my assessment:" — which consumes the limited bar space without conveying useful info. The actual substance is on subsequent lines that get cut.

## Current Logic

`updateStrategyPanel()` at line ~9583:
```js
var firstLine = raw.split('\n').filter(function(l){ return l.trim(); })[0] || raw;
var summary = firstLine.length > 200 ? firstLine.substring(0, 200) + '…' : firstLine;
```

Takes first non-empty line, truncates to 200 chars.

## Fix Options

### Option A: Skip preamble lines
Filter out generic preambles before selecting the first line:
```js
var lines = raw.split('\n').filter(function(l) {
    var t = l.trim();
    if (!t) return false;
    // Skip generic preambles
    if (/^(Strategy posted|Here's my|Let me|I'll|Current state)/i.test(t)) return false;
    return true;
});
var firstLine = lines[0] || raw.split('\n')[0] || raw;
```

### Option B: Allow 2 lines in bar
Increase bar height to show 2 lines of content. CSS change on `.strategy-bar-directive`.

### Option C: Better ST prompt
Tell ST to lead with the actionable insight, not a preamble:
"When posting strategy updates, lead with the key decision or finding. Do NOT start with 'Strategy posted' or 'Here's my assessment'."

### Recommendation
Option A + C — skip preambles in code AND tell ST to lead with substance.
