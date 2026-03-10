# Internet Outage Detection — Design

**Goal:** Auto-pause ATHENA agents when internet connectivity is lost, auto-resume when it returns, with a dashboard banner.

## Architecture

A background `asyncio` task in `server.py` pings `https://www.google.com/generate_204` (expects HTTP 204) every 10 seconds. After 2 consecutive failures, it sets a `_network_down` flag and calls `_active_session_manager.pause()`. After 1 success, it clears the flag and calls `resume()`. A WebSocket event notifies the frontend to show/hide a banner.

## Detection Parameters

- **Ping target:** `https://www.google.com/generate_204` (Google captive portal check, returns 204)
- **Poll interval:** 10 seconds
- **Outage threshold:** 2 consecutive failures (20s)
- **Recovery threshold:** 1 success
- **Request timeout:** 5 seconds

## Components

### 1. Connectivity Monitor (`server.py`)

- Background task started with the server (`@app.on_event("startup")`)
- `httpx.AsyncClient` GET request to `https://www.google.com/generate_204` with 5s timeout
- State: `_network_down: bool`, `_consecutive_failures: int`, `_network_down_since: float | None`
- On outage: broadcast `{"type": "network_status", "status": "down"}`, auto-pause
- On recovery: broadcast `{"type": "network_status", "status": "up"}`, auto-resume with message "Internet connectivity restored. Continue your task."

### 2. Dashboard Banner (`index.html`)

- Fixed banner at top of main content area
- Text: "Internet connectivity lost — agents paused, waiting for recovery..."
- Yellow/warning color with pulse animation
- Auto-hides on `network_status: up` event
- Shows elapsed downtime (updates every second via JS interval)

### 3. No changes to `sdk_agent.py` or `agent_session_manager.py`

Leverages existing `pause()`/`resume()` API and `_paused` flag from BUG-029 fix.

## Data Flow

```
Monitor task (10s loop)
  -> GET google.com/generate_204 (5s timeout)
  -> 2 failures -> _network_down = true
    -> session_manager.pause()
    -> WS broadcast: network_status: down
    -> Frontend: show banner
  -> 1 success -> _network_down = false
    -> session_manager.resume()
    -> WS broadcast: network_status: up
    -> Frontend: hide banner
```

## Edge Cases

- **Server starts with no internet:** Monitor detects immediately, no engagement to pause. Banner shows.
- **Outage during no active engagement:** Flag set, no pause/resume needed. Banner still shows.
- **Manual pause + outage:** Track `_user_paused` vs `_network_paused` separately. Don't auto-resume if user manually paused.
- **Flapping:** 2-failure threshold prevents single-packet false positives.
- **Recovery during pause:** On resume, agents get message "Internet connectivity restored. Continue your task." and pick up where they left off.

## Files Modified

- `server.py` — Add connectivity monitor background task, WS event broadcast, `_network_down` state
- `index.html` — Add network banner HTML, WS handler for `network_status` events, elapsed timer
- `agent_session_manager.py` — Add `_network_paused` flag to distinguish from user pause (prevents auto-resume overriding manual pause)
