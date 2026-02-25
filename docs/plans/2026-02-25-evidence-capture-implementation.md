# Evidence Capture System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add automated evidence capture (screenshots, HTTP pairs, command output, diffs) to ATHENA's verify agent, with Neo4j-linked Artifact nodes, dashboard evidence gallery, inline report integration, and client ZIP packaging.

**Architecture:** Hybrid filesystem + Neo4j metadata. Binary artifacts stored on disk (engagement evidence folders), metadata in Neo4j with SHA-256 chain of custody. Dashboard serves files via dedicated API endpoints. Dual Kali backends (external Antsle + internal mini-PC) store evidence locally; server fetches via SCP when needed.

**Tech Stack:** FastAPI (Python), Neo4j (Cypher), vanilla JS/HTML/CSS (ATHENA dashboard), Playwright MCP (screenshots), Pillow (thumbnails)

**Design Doc:** `docs/plans/2026-02-25-evidence-capture-system-design.md`

---

## Critical Context for Implementer

### Known Bugs to Fix During Implementation

1. **Relationship name mismatch:** `athena-verify.md` writes `(ep)-[:SUPPORTS]->(f)` but `server.py:1911` queries `(f)-[:EVIDENCED_BY]->(ep)`. **Standardize on `EVIDENCED_BY`** — update the agent.

2. **EvidencePackage field mismatch:** Agent writes `http_pairs`, `output_evidence`, `response_diff`. Server reads `request`, `response`, `screenshot`, `notes`, `type`. **Update server endpoint to read agent's field names.**

### Key Integration Points (Already Wired)

- `UploadFile` and `StaticFiles` already imported in server.py (lines 50, 52)
- `evidence_count` already rendered in findings table (from `count(DISTINCT ep)` query)
- `loadEvidence(findingId)` already called on finding expand (line 9718)
- `ev.screenshot` already has `<img>` tag rendering (line 9741)
- Evidence CSS classes already defined (lines 2476-2510)

### File Locations

| File | Path | Lines |
|------|------|-------|
| API server | `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard/server.py` | 4,117 |
| Dashboard | `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard/index.html` | 9,897 |
| Verify agent | `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/.claude/agents/athena-verify.md` | ~600 |
| Report agent | `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/.claude/agents/athena-report.md` | ~230 |
| Tool registry | `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard/tool-registry.json` | ~400 |
| Startup script | `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard/start.sh` | 26 |

### Neo4j Connection

- URI: `bolt://kali.linux.vkloud.antsle.us:7687`
- Auth: `neo4j/athena2026`
- Pattern: optional — all writes fall through to in-memory state if Neo4j unavailable

### Dual Kali Backends

| Backend | SSH | User | Evidence Path |
|---------|-----|------|---------------|
| External (Antsle) | `kali.linux.vkloud.antsle.us:2222` | `kelvin` | `/home/kelvin/athena/engagements/{eid}/08-evidence/` |
| Internal (mini-PC) | `172.26.80.76:3113` | `pentester_0k` | `/home/pentester_0k/athena/engagements/{eid}/08-evidence/` |

---

## Task 1: Evidence Directory Structure + Pillow Dependency

**Files:**
- Modify: `tools/athena-dashboard/start.sh`
- Modify: `tools/athena-dashboard/requirements.txt`
- Modify: `tools/athena-dashboard/server.py` (add evidence dir constants + mkdir in engagement creation)

**Step 1: Add Pillow to requirements.txt**

Read `tools/athena-dashboard/requirements.txt` and add `Pillow>=10.0.0` for thumbnail generation.

**Step 2: Add evidence directory constants to server.py**

After the existing path constants (near line 200), add:

```python
# Evidence directory structure
EVIDENCE_SUBFOLDERS = ["screenshots", "screenshots/thumbnails", "http-pairs", "command-output", "tool-logs", "response-diffs"]

def ensure_evidence_dirs(engagement_id: str) -> Path:
    """Create evidence directory structure for an engagement. Returns the evidence root."""
    athena_dir = Path(__file__).parent.parent.parent
    evidence_root = athena_dir / "engagements" / "active" / engagement_id / "08-evidence"
    for subfolder in EVIDENCE_SUBFOLDERS:
        (evidence_root / subfolder).mkdir(parents=True, exist_ok=True)
    return evidence_root
```

**Step 3: Wire into engagement creation endpoint**

Find `POST /api/engagements` in server.py. After the Neo4j Engagement node is created, call:

```python
ensure_evidence_dirs(engagement_id)
```

**Step 4: Verify manually**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/pip install Pillow>=10.0.0
```

Then restart server and create a test engagement via the dashboard. Verify:

```bash
ls -la /Users/kelvinlomboy/VERSANT/Projects/ATHENA/engagements/active/*/08-evidence/
```

Expected: `screenshots/`, `screenshots/thumbnails/`, `http-pairs/`, `command-output/`, `tool-logs/`, `response-diffs/`

**Step 5: Commit**

```bash
git add tools/athena-dashboard/requirements.txt tools/athena-dashboard/server.py
git commit -m "feat: evidence directory structure + Pillow dependency"
```

---

## Task 2: Artifact Upload Endpoint (POST /api/artifacts)

**Files:**
- Modify: `tools/athena-dashboard/server.py`

**Step 1: Add Artifact Pydantic model and imports**

Near the existing model definitions (around line 818), add:

```python
import hashlib
from PIL import Image
from io import BytesIO

ALLOWED_ARTIFACT_TYPES = {"screenshot", "http_pair", "command_output", "tool_log", "response_diff"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "text/plain", "application/json", "application/xml", "text/html"}
MAX_ARTIFACT_SIZE = 2 * 1024 * 1024  # 2MB
THUMBNAIL_WIDTH = 300
THUMBNAIL_QUALITY = 75
```

**Step 2: Implement POST /api/artifacts**

Add after the existing evidence endpoint (~line 1945):

```python
@app.post("/api/artifacts")
async def upload_artifact(
    file: UploadFile,
    finding_id: str = Form(...),
    engagement_id: str = Form(...),
    type: str = Form(...),
    caption: str = Form(""),
    agent: str = Form("unknown"),
    backend: str = Form("external"),
    capture_mode: str = Form("exploitable"),
    evidence_package_id: str = Form(None),
):
    """Upload an evidence artifact and link it to a Finding in Neo4j."""
    # Validate type
    if type not in ALLOWED_ARTIFACT_TYPES:
        return JSONResponse(status_code=400, content={"error": f"Invalid type. Must be one of: {ALLOWED_ARTIFACT_TYPES}"})

    # Read file content
    content = await file.read()
    if len(content) > MAX_ARTIFACT_SIZE:
        return JSONResponse(status_code=400, content={"error": f"File exceeds {MAX_ARTIFACT_SIZE // (1024*1024)}MB limit"})

    # Compute SHA-256
    file_hash = hashlib.sha256(content).hexdigest()

    # Determine subfolder and extension
    subfolder_map = {
        "screenshot": "screenshots",
        "http_pair": "http-pairs",
        "command_output": "command-output",
        "tool_log": "tool-logs",
        "response_diff": "response-diffs",
    }
    subfolder = subfolder_map[type]

    # Generate artifact ID and filename
    artifact_id = f"art-{uuid.uuid4().hex[:8]}"
    ext = Path(file.filename).suffix if file.filename else ".bin"
    timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Build filename using naming convention
    # Query finding severity from Neo4j or in-memory
    severity = "INFO"
    category = "GEN"
    if neo4j_available:
        with neo4j_driver.session() as session:
            result = session.run(
                "MATCH (f:Finding {id: $fid}) RETURN f.severity AS sev, f.category AS cat",
                fid=finding_id
            )
            record = result.single()
            if record:
                severity = (record["sev"] or "info").upper()
                category = (record["cat"] or "GEN").upper()

    safe_caption = caption.replace(" ", "-").replace("/", "-")[:40].lower()
    filename = f"{artifact_id}-{severity}-{category}-{safe_caption}-{timestamp_str}{ext}"

    # Ensure evidence dirs exist
    evidence_root = ensure_evidence_dirs(engagement_id)
    file_path = evidence_root / subfolder / filename
    file_path.write_bytes(content)

    # Generate thumbnail for screenshots
    thumbnail_path = None
    if type == "screenshot" and ext.lower() in (".png", ".jpg", ".jpeg"):
        try:
            img = Image.open(BytesIO(content))
            ratio = THUMBNAIL_WIDTH / img.width
            thumb_size = (THUMBNAIL_WIDTH, int(img.height * ratio))
            img.thumbnail(thumb_size, Image.LANCZOS)
            thumb_filename = f"{artifact_id}-thumb.jpg"
            thumb_full_path = evidence_root / "screenshots" / "thumbnails" / thumb_filename
            img.save(thumb_full_path, "JPEG", quality=THUMBNAIL_QUALITY)
            thumbnail_path = str(thumb_full_path.relative_to(Path(__file__).parent.parent.parent))
        except Exception:
            pass  # Thumbnail generation is non-critical

    # Relative path for portability
    relative_path = str(file_path.relative_to(Path(__file__).parent.parent.parent))

    # Store in Neo4j
    mime_type = file.content_type or "application/octet-stream"
    timestamp = datetime.now().isoformat()

    if neo4j_available:
        with neo4j_driver.session() as session:
            session.run("""
                CREATE (a:Artifact {
                    id: $aid, engagement_id: $eid, finding_id: $fid,
                    evidence_package_id: $epid, type: $type,
                    file_path: $fpath, file_hash: $fhash, file_size: $fsize,
                    mime_type: $mime, caption: $caption, agent: $agent,
                    backend: $backend, capture_mode: $mode,
                    thumbnail_path: $thumb, timestamp: $ts
                })
                WITH a
                MATCH (f:Finding {id: $fid})
                MERGE (f)-[:HAS_ARTIFACT]->(a)
            """, aid=artifact_id, eid=engagement_id, fid=finding_id,
                epid=evidence_package_id, type=type, fpath=relative_path,
                fhash=file_hash, fsize=len(content), mime=mime_type,
                caption=caption, agent=agent, backend=backend,
                mode=capture_mode, thumb=thumbnail_path, ts=timestamp)

            # Link to EvidencePackage if provided
            if evidence_package_id:
                session.run("""
                    MATCH (ep:EvidencePackage {id: $epid}), (a:Artifact {id: $aid})
                    MERGE (ep)-[:HAS_ARTIFACT]->(a)
                """, epid=evidence_package_id, aid=artifact_id)

    return {
        "ok": True,
        "artifact": {
            "id": artifact_id,
            "file_path": relative_path,
            "file_hash": file_hash,
            "file_size": len(content),
            "thumbnail_path": thumbnail_path,
            "type": type,
            "caption": caption,
            "timestamp": timestamp,
        }
    }
```

**Step 3: Verify with curl**

```bash
# Upload a test screenshot
curl -X POST http://localhost:8080/api/artifacts \
  -F "file=@/tmp/test-screenshot.png" \
  -F "finding_id=test-f001" \
  -F "engagement_id=eng-001" \
  -F "type=screenshot" \
  -F "caption=Test screenshot" \
  -F "agent=manual" \
  -F "backend=external"
```

Expected: `{"ok": true, "artifact": {"id": "art-...", "file_hash": "...", ...}}`

**Step 4: Commit**

```bash
git add tools/athena-dashboard/server.py
git commit -m "feat: artifact upload endpoint with SHA-256 hashing and thumbnails"
```

---

## Task 3: Artifact Query + File Serving Endpoints

**Files:**
- Modify: `tools/athena-dashboard/server.py`

**Step 1: Add GET /api/artifacts (list with filters)**

```python
@app.get("/api/artifacts")
async def list_artifacts(
    engagement_id: str = None,
    finding_id: str = None,
    type: str = None,
    backend: str = None,
    capture_mode: str = None,
    limit: int = 100,
    offset: int = 0,
):
    """List artifacts with optional filters."""
    if not neo4j_available:
        return {"artifacts": [], "source": "none"}

    # Build dynamic WHERE clause
    conditions = []
    params = {"limit": limit, "offset": offset}
    if engagement_id:
        conditions.append("a.engagement_id = $eid")
        params["eid"] = engagement_id
    if finding_id:
        conditions.append("a.finding_id = $fid")
        params["fid"] = finding_id
    if type:
        conditions.append("a.type = $atype")
        params["atype"] = type
    if backend:
        conditions.append("a.backend = $backend")
        params["backend"] = backend
    if capture_mode:
        conditions.append("a.capture_mode = $mode")
        params["mode"] = capture_mode

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    with neo4j_driver.session() as session:
        result = session.run(f"""
            MATCH (a:Artifact)
            {where_clause}
            OPTIONAL MATCH (f:Finding {{id: a.finding_id}})
            RETURN a.id AS id, a.type AS type, a.caption AS caption,
                   a.finding_id AS finding_id, a.file_path AS file_path,
                   a.file_hash AS file_hash, a.file_size AS file_size,
                   a.mime_type AS mime_type, a.agent AS agent,
                   a.backend AS backend, a.capture_mode AS capture_mode,
                   a.thumbnail_path AS thumbnail_path, a.timestamp AS timestamp,
                   f.severity AS severity, f.title AS finding_title
            ORDER BY a.timestamp DESC
            SKIP $offset LIMIT $limit
        """, **params)

        artifacts = [dict(record) for record in result]

    return {"artifacts": artifacts, "total": len(artifacts)}
```

**Step 2: Add GET /api/artifacts/{artifact_id}/file (serve binary)**

```python
@app.get("/api/artifacts/{artifact_id}/file")
async def serve_artifact_file(artifact_id: str):
    """Serve an artifact file from disk."""
    if not neo4j_available:
        return JSONResponse(status_code=404, content={"error": "Neo4j unavailable"})

    with neo4j_driver.session() as session:
        result = session.run(
            "MATCH (a:Artifact {id: $aid}) RETURN a.file_path AS fp, a.mime_type AS mime, a.backend AS backend",
            aid=artifact_id
        )
        record = result.single()
        if not record:
            return JSONResponse(status_code=404, content={"error": "Artifact not found"})

    athena_dir = Path(__file__).parent.parent.parent
    file_path = athena_dir / record["fp"]

    if not file_path.exists():
        # TODO: Future — SCP from remote Kali backend if file not local
        return JSONResponse(status_code=404, content={"error": f"File not found on disk: {record['fp']}"})

    return FileResponse(
        path=str(file_path),
        media_type=record["mime"] or "application/octet-stream",
        filename=file_path.name
    )
```

**Step 3: Add GET /api/artifacts/{artifact_id}/thumbnail**

```python
@app.get("/api/artifacts/{artifact_id}/thumbnail")
async def serve_artifact_thumbnail(artifact_id: str):
    """Serve a thumbnail for a screenshot artifact."""
    if not neo4j_available:
        return JSONResponse(status_code=404, content={"error": "Neo4j unavailable"})

    with neo4j_driver.session() as session:
        result = session.run(
            "MATCH (a:Artifact {id: $aid}) RETURN a.thumbnail_path AS tp, a.file_path AS fp",
            aid=artifact_id
        )
        record = result.single()
        if not record:
            return JSONResponse(status_code=404, content={"error": "Artifact not found"})

    athena_dir = Path(__file__).parent.parent.parent

    # Try thumbnail first, fall back to full image
    if record["tp"]:
        thumb_path = athena_dir / record["tp"]
        if thumb_path.exists():
            return FileResponse(path=str(thumb_path), media_type="image/jpeg")

    # Fallback to full file
    file_path = athena_dir / record["fp"]
    if file_path.exists():
        return FileResponse(path=str(file_path), media_type="image/png")

    return JSONResponse(status_code=404, content={"error": "Thumbnail not found"})
```

**Step 4: Add DELETE /api/artifacts/{artifact_id}**

```python
@app.delete("/api/artifacts/{artifact_id}")
async def delete_artifact(artifact_id: str):
    """Delete an artifact from Neo4j and disk."""
    if not neo4j_available:
        return JSONResponse(status_code=500, content={"error": "Neo4j unavailable"})

    with neo4j_driver.session() as session:
        result = session.run(
            "MATCH (a:Artifact {id: $aid}) RETURN a.file_path AS fp, a.thumbnail_path AS tp",
            aid=artifact_id
        )
        record = result.single()
        if not record:
            return JSONResponse(status_code=404, content={"error": "Artifact not found"})

        # Delete files from disk
        athena_dir = Path(__file__).parent.parent.parent
        for path_field in [record["fp"], record["tp"]]:
            if path_field:
                full_path = athena_dir / path_field
                if full_path.exists():
                    full_path.unlink()

        # Delete from Neo4j
        session.run("MATCH (a:Artifact {id: $aid}) DETACH DELETE a", aid=artifact_id)

    return {"ok": True, "deleted": artifact_id}
```

**Step 5: Verify**

```bash
# List artifacts for an engagement
curl http://localhost:8080/api/artifacts?engagement_id=eng-001

# Serve a file (use artifact ID from task 2)
curl -o /tmp/test-download.png http://localhost:8080/api/artifacts/art-XXXX/file

# Serve thumbnail
curl -o /tmp/test-thumb.jpg http://localhost:8080/api/artifacts/art-XXXX/thumbnail
```

**Step 6: Commit**

```bash
git add tools/athena-dashboard/server.py
git commit -m "feat: artifact query, file serving, thumbnail, and delete endpoints"
```

---

## Task 4: Evidence Stats + Manifest + ZIP Packaging Endpoints

**Files:**
- Modify: `tools/athena-dashboard/server.py`

**Step 1: Add GET /api/evidence/stats**

```python
@app.get("/api/evidence/stats")
async def evidence_stats(engagement_id: str):
    """Return evidence statistics for an engagement."""
    if not neo4j_available:
        return {"total_artifacts": 0, "coverage": {"percent": 0}}

    with neo4j_driver.session() as session:
        result = session.run("""
            MATCH (a:Artifact {engagement_id: $eid})
            OPTIONAL MATCH (f:Finding {id: a.finding_id})
            WITH a, f
            RETURN
                count(a) AS total,
                sum(a.file_size) AS total_size,
                collect(DISTINCT a.type) AS types,
                count(DISTINCT a.finding_id) AS findings_with_evidence,
                collect({type: a.type, severity: f.severity, backend: a.backend, mode: a.capture_mode}) AS details
        """, eid=engagement_id)
        record = result.single()

        # Count findings total
        total_findings_result = session.run(
            "MATCH (f:Finding {engagement_id: $eid}) RETURN count(f) AS total",
            eid=engagement_id
        )
        total_findings = total_findings_result.single()["total"]

    details = record["details"] if record else []
    by_type = {}
    by_severity = {}
    by_backend = {}
    by_mode = {}
    for d in details:
        by_type[d["type"]] = by_type.get(d["type"], 0) + 1
        if d["severity"]:
            sev = d["severity"].lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        if d["backend"]:
            by_backend[d["backend"]] = by_backend.get(d["backend"], 0) + 1
        if d["mode"]:
            by_mode[d["mode"]] = by_mode.get(d["mode"], 0) + 1

    findings_with = record["findings_with_evidence"] if record else 0
    coverage_pct = round((findings_with / total_findings * 100) if total_findings > 0 else 0, 1)

    return {
        "total_artifacts": record["total"] if record else 0,
        "total_size_bytes": record["total_size"] if record else 0,
        "by_type": by_type,
        "by_severity": by_severity,
        "by_backend": by_backend,
        "by_mode": by_mode,
        "coverage": {
            "findings_with_evidence": findings_with,
            "findings_total": total_findings,
            "percent": coverage_pct,
        }
    }
```

**Step 2: Add GET /api/evidence/manifest**

```python
@app.get("/api/evidence/manifest")
async def evidence_manifest(engagement_id: str):
    """Generate evidence manifest JSON for an engagement."""
    if not neo4j_available:
        return {"engagement_id": engagement_id, "artifacts": []}

    with neo4j_driver.session() as session:
        result = session.run("""
            MATCH (a:Artifact {engagement_id: $eid})
            OPTIONAL MATCH (f:Finding {id: a.finding_id})
            RETURN a, f.title AS finding_title, f.severity AS finding_severity
            ORDER BY a.timestamp
        """, eid=engagement_id)

        artifacts = []
        for record in result:
            a = record["a"]
            artifacts.append({
                "id": a["id"],
                "finding_id": a["finding_id"],
                "finding_title": record["finding_title"],
                "finding_severity": record["finding_severity"],
                "type": a["type"],
                "file_path": a["file_path"],
                "file_hash": f"sha256:{a['file_hash']}",
                "file_size": a["file_size"],
                "mime_type": a["mime_type"],
                "caption": a["caption"],
                "agent": a["agent"],
                "backend": a["backend"],
                "capture_mode": a["capture_mode"],
                "timestamp": a["timestamp"],
            })

    return {
        "engagement_id": engagement_id,
        "generated": datetime.now().isoformat(),
        "total_artifacts": len(artifacts),
        "artifacts": artifacts,
    }
```

**Step 3: Add POST /api/evidence/package (ZIP generation)**

```python
import zipfile
import tempfile

@app.post("/api/evidence/package")
async def create_evidence_package(engagement_id: str):
    """Generate a client-ready ZIP with evidence + manifest."""
    athena_dir = Path(__file__).parent.parent.parent

    # Find evidence root
    evidence_candidates = list((athena_dir / "engagements" / "active").glob(f"{engagement_id}*/08-evidence"))
    if not evidence_candidates:
        return JSONResponse(status_code=404, content={"error": "No evidence directory found"})
    evidence_root = evidence_candidates[0]

    # Generate manifest
    manifest = await evidence_manifest(engagement_id)

    # Create ZIP
    zip_filename = f"{engagement_id}-evidence-package-{datetime.now().strftime('%Y%m%d')}.zip"
    zip_path = athena_dir / "output" / zip_filename
    (athena_dir / "output").mkdir(exist_ok=True)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add evidence files
        for root, dirs, files in os.walk(evidence_root):
            for f in files:
                full_path = Path(root) / f
                arcname = f"08-evidence/{full_path.relative_to(evidence_root)}"
                zf.write(full_path, arcname)

        # Add manifest
        import json
        zf.writestr("evidence-manifest.json", json.dumps(manifest, indent=2))

        # Add report if exists
        report_dir = evidence_root.parent / "09-reporting"
        if report_dir.exists():
            for report_file in report_dir.glob("*.md"):
                zf.write(report_file, f"09-reporting/{report_file.name}")

    return {
        "ok": True,
        "package": {
            "filename": zip_filename,
            "path": str(zip_path),
            "size_bytes": zip_path.stat().st_size,
            "download_url": f"/api/evidence/package/{engagement_id}/download",
        }
    }

@app.get("/api/evidence/package/{engagement_id}/download")
async def download_evidence_package(engagement_id: str):
    """Download a previously generated evidence package."""
    athena_dir = Path(__file__).parent.parent.parent
    output_dir = athena_dir / "output"

    # Find most recent package for this engagement
    packages = sorted(output_dir.glob(f"{engagement_id}-evidence-package-*.zip"), reverse=True)
    if not packages:
        return JSONResponse(status_code=404, content={"error": "No package found. Generate one first."})

    return FileResponse(
        path=str(packages[0]),
        media_type="application/zip",
        filename=packages[0].name
    )
```

**Step 4: Verify**

```bash
# Evidence stats
curl http://localhost:8080/api/evidence/stats?engagement_id=eng-001

# Generate manifest
curl http://localhost:8080/api/evidence/manifest?engagement_id=eng-001

# Create package
curl -X POST http://localhost:8080/api/evidence/package?engagement_id=eng-001

# Download package
curl -o /tmp/evidence.zip http://localhost:8080/api/evidence/package/eng-001/download
```

**Step 5: Commit**

```bash
git add tools/athena-dashboard/server.py
git commit -m "feat: evidence stats, manifest generation, and ZIP packaging endpoints"
```

---

## Task 5: Fix Evidence Query Endpoint + Relationship Mismatch

**Files:**
- Modify: `tools/athena-dashboard/server.py` (~line 1905)

**Step 1: Update GET /api/engagements/{eid}/findings/{fid}/evidence**

The existing endpoint at line 1905 queries `[:EVIDENCED_BY]` and reads fields that don't match what the agent writes. Update it to:

1. Query both `[:EVIDENCED_BY]` and `[:HAS_ARTIFACT]` relationships
2. Return Artifact nodes alongside EvidencePackage nodes
3. Map the agent's actual field names

```python
@app.get("/api/engagements/{eid}/findings/{fid}/evidence")
async def get_finding_evidence(eid: str, fid: str):
    """Get all evidence for a finding — EvidencePackages + Artifacts."""
    if not neo4j_available:
        return {"evidence": [], "artifacts": [], "source": "none"}

    with neo4j_driver.session() as session:
        # Get EvidencePackages (linked via EVIDENCED_BY or SUPPORTS)
        ep_result = session.run("""
            MATCH (f:Finding {id: $fid})
            OPTIONAL MATCH (f)-[:EVIDENCED_BY|SUPPORTS]-(ep:EvidencePackage)
            RETURN ep.id AS id, ep.verification_method AS type,
                   ep.http_pairs AS http_pairs,
                   ep.output_evidence AS output_evidence,
                   ep.response_diff AS response_diff,
                   ep.timing_baseline_ms AS timing_baseline,
                   ep.timing_exploit_ms AS timing_exploit,
                   ep.confidence AS confidence,
                   ep.status AS status,
                   ep.verified_by AS verified_by,
                   ep.timestamp AS timestamp
            ORDER BY ep.timestamp DESC
        """, fid=fid)
        evidence_packages = [dict(r) for r in ep_result if r["id"]]

        # Get Artifacts (linked via HAS_ARTIFACT)
        art_result = session.run("""
            MATCH (f:Finding {id: $fid})-[:HAS_ARTIFACT]->(a:Artifact)
            RETURN a.id AS id, a.type AS type, a.caption AS caption,
                   a.file_path AS file_path, a.file_hash AS file_hash,
                   a.file_size AS file_size, a.mime_type AS mime_type,
                   a.agent AS agent, a.backend AS backend,
                   a.capture_mode AS capture_mode,
                   a.thumbnail_path AS thumbnail_path,
                   a.timestamp AS timestamp
            ORDER BY a.timestamp
        """, fid=fid)
        artifacts = [dict(r) for r in art_result]

    return {
        "evidence_packages": evidence_packages,
        "artifacts": artifacts,
        "source": "neo4j"
    }
```

**Step 2: Update the findings list query to count artifacts**

Find the `GET /api/engagements/{eid}/findings` endpoint (~line 1403). Update the Cypher to count both EvidencePackage and Artifact nodes:

In the existing query, after:
```cypher
OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
```

Add:
```cypher
OPTIONAL MATCH (f)-[:HAS_ARTIFACT]->(art:Artifact)
```

And update the RETURN to include:
```cypher
count(DISTINCT ep) + count(DISTINCT art) AS evidence_count
```

**Step 3: Verify**

```bash
curl http://localhost:8080/api/engagements/eng-001/findings/test-f001/evidence
```

Expected: `{"evidence_packages": [...], "artifacts": [...], "source": "neo4j"}`

**Step 4: Commit**

```bash
git add tools/athena-dashboard/server.py
git commit -m "fix: evidence query supports both EvidencePackage and Artifact nodes"
```

---

## Task 6: Frontend — Enhanced Evidence Rendering in Finding Detail

**Files:**
- Modify: `tools/athena-dashboard/index.html`

**Step 1: Update loadEvidence() function (~line 9718)**

Replace the existing `loadEvidence` function to handle the new response format with both `evidence_packages` and `artifacts`:

```javascript
async function loadEvidence(findingId) {
    const container = document.getElementById(`evidence-${findingId}`);
    if (!container) return;
    container.innerHTML = '<div style="color: var(--zerok-text-muted); padding: 12px;">Loading evidence...</div>';

    try {
        const resp = await fetch(`/api/engagements/${currentEngagementId}/findings/${findingId}/evidence`);
        const data = await resp.json();

        const packages = data.evidence_packages || [];
        const artifacts = data.artifacts || [];

        if (packages.length === 0 && artifacts.length === 0) {
            container.innerHTML = '<div style="color: var(--zerok-text-dim); padding: 12px; font-style: italic;">No evidence captured yet</div>';
            return;
        }

        let html = '';

        // Render artifacts (screenshots, HTTP pairs, command output, etc.)
        if (artifacts.length > 0) {
            html += '<div class="evidence-artifacts-grid">';
            for (const art of artifacts) {
                html += renderArtifactCard(art);
            }
            html += '</div>';
        }

        // Render evidence packages (structured verification data)
        for (const ep of packages) {
            html += renderEvidencePackage(ep);
        }

        container.innerHTML = html;
    } catch (err) {
        container.innerHTML = `<div style="color: var(--zerok-critical); padding: 12px;">Error loading evidence: ${err.message}</div>`;
    }
}

function renderArtifactCard(art) {
    const typeIcons = {
        screenshot: '\u{1F4F7}',
        http_pair: '\u{1F4CB}',
        command_output: '\u{1F5A5}',
        tool_log: '\u{1F4C4}',
        response_diff: '\u{1F504}',
    };
    const icon = typeIcons[art.type] || '\u{1F4CE}';
    const isImage = art.type === 'screenshot';

    let content = '';
    if (isImage) {
        content = `
            <div class="artifact-thumbnail" onclick="showArtifactFullsize('${art.id}')">
                <img src="/api/artifacts/${art.id}/thumbnail" alt="${art.caption || 'Screenshot'}"
                     loading="lazy" style="width: 100%; border-radius: 4px; cursor: pointer;">
            </div>`;
    } else {
        content = `
            <div class="artifact-preview" onclick="showArtifactFullsize('${art.id}')" style="cursor: pointer;">
                <span style="font-size: 2em;">${icon}</span>
                <div style="color: var(--zerok-text-muted); font-size: 0.8em; margin-top: 4px;">Click to view</div>
            </div>`;
    }

    const modeLabel = art.capture_mode === 'observable'
        ? '<span style="color: var(--zerok-info); font-size: 0.7em; text-transform: uppercase;">Observable</span>'
        : '';

    return `
        <div class="artifact-card" data-artifact-id="${art.id}">
            ${content}
            <div class="artifact-meta">
                <div style="font-size: 0.85em; color: var(--zerok-text); margin-top: 6px;">
                    ${icon} ${art.caption || art.type}
                </div>
                <div style="font-size: 0.7em; color: var(--zerok-text-dim); margin-top: 2px;">
                    ${art.agent || ''} &middot; ${art.backend || ''} ${modeLabel}
                </div>
                <div style="font-size: 0.65em; color: var(--zerok-text-dim); font-family: var(--zerok-font-mono);">
                    SHA-256: ${(art.file_hash || '').substring(0, 16)}...
                </div>
            </div>
        </div>`;
}

function renderEvidencePackage(ep) {
    const confidenceColors = {
        HIGH: 'var(--zerok-low)',       // green
        MEDIUM: 'var(--zerok-medium)',  // yellow
        LOW: 'var(--zerok-high)',       // orange
    };
    const color = confidenceColors[ep.confidence] || 'var(--zerok-text-dim)';

    let html = `<div class="evidence-item" style="margin-top: 12px;">
        <div class="evidence-header">
            <span class="evidence-type">${ep.type || 'Verification'}</span>
            <span style="color: ${color}; font-weight: 600; font-size: 0.8em;">${ep.confidence || 'N/A'} confidence</span>
        </div>`;

    if (ep.http_pairs) {
        html += `<div class="evidence-block"><pre style="white-space: pre-wrap; max-height: 200px; overflow-y: auto;">${escapeHtml(ep.http_pairs)}</pre></div>`;
    }
    if (ep.output_evidence) {
        html += `<div class="evidence-block"><pre style="white-space: pre-wrap; max-height: 150px; overflow-y: auto;">${escapeHtml(ep.output_evidence)}</pre></div>`;
    }
    if (ep.response_diff) {
        html += `<div class="evidence-block"><pre style="white-space: pre-wrap; max-height: 150px; overflow-y: auto;">${escapeHtml(ep.response_diff)}</pre></div>`;
    }

    html += `<div style="font-size: 0.7em; color: var(--zerok-text-dim); margin-top: 6px;">
        Verified by: ${ep.verified_by || 'unknown'} &middot; ${ep.timestamp || ''}
    </div></div>`;

    return html;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
```

**Step 2: Add fullsize artifact viewer (lightbox)**

```javascript
function showArtifactFullsize(artifactId) {
    // Remove existing overlay
    const existing = document.getElementById('artifact-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'artifact-overlay';
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.9); z-index: 10000;
        display: flex; align-items: center; justify-content: center;
        cursor: pointer;
    `;
    overlay.onclick = () => overlay.remove();

    const img = document.createElement('img');
    img.src = `/api/artifacts/${artifactId}/file`;
    img.style.cssText = 'max-width: 90vw; max-height: 90vh; border-radius: 8px; box-shadow: 0 0 40px rgba(0,0,0,0.5);';
    img.onclick = (e) => e.stopPropagation();

    overlay.appendChild(img);
    document.body.appendChild(overlay);

    // Close on Escape
    const handler = (e) => { if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', handler); } };
    document.addEventListener('keydown', handler);
}
```

**Step 3: Add CSS for artifact grid and cards**

After the existing `.evidence-gallery` CSS (~line 2510), add:

```css
.evidence-artifacts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 12px;
}

.artifact-card {
    background: var(--zerok-bg-alt);
    border: 1px solid var(--zerok-border);
    border-radius: 8px;
    padding: 8px;
    transition: border-color 0.2s;
}

.artifact-card:hover {
    border-color: var(--zerok-primary);
}

.artifact-thumbnail img {
    border-radius: 4px;
    aspect-ratio: 16/10;
    object-fit: cover;
}

.artifact-preview {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 80px;
    background: var(--zerok-bg);
    border-radius: 4px;
}

.artifact-meta {
    padding: 4px 0;
}
```

**Step 4: Verify in browser**

Navigate to `http://localhost:8080`, open an engagement, expand a finding that has artifacts uploaded (from Task 2 manual test). Confirm:
- Artifact grid renders with thumbnail
- Click thumbnail opens fullsize overlay
- Escape closes overlay
- Evidence packages render with HTTP pairs, confidence

**Step 5: Commit**

```bash
git add tools/athena-dashboard/index.html
git commit -m "feat: enhanced evidence rendering with artifact grid, lightbox, and confidence display"
```

---

## Task 7: Frontend — Evidence Gallery Page

**Files:**
- Modify: `tools/athena-dashboard/index.html`

**Step 1: Add Evidence nav item**

In the navigation section (~line 4453), after the Findings nav item, add:

```html
<button class="nav-item" data-view="evidence" title="Evidence Gallery">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
        <circle cx="8.5" cy="8.5" r="1.5"></circle>
        <polyline points="21 15 16 10 5 21"></polyline>
    </svg>
    <span class="nav-label">Evidence</span>
</button>
```

**Step 2: Add Evidence view container**

After the existing view containers (find the pattern of `<div class="view" id="XXX-view">`), add:

```html
<div class="view" id="evidence-view" style="display: none;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h2 style="margin: 0; color: var(--zerok-text);">Evidence Gallery</h2>
        <div style="display: flex; gap: 8px;">
            <select id="evidence-filter-type" onchange="loadEvidenceGallery()" style="background: var(--zerok-bg-alt); color: var(--zerok-text); border: 1px solid var(--zerok-border); border-radius: 4px; padding: 4px 8px;">
                <option value="">All Types</option>
                <option value="screenshot">Screenshots</option>
                <option value="http_pair">HTTP Pairs</option>
                <option value="command_output">Command Output</option>
                <option value="tool_log">Tool Logs</option>
                <option value="response_diff">Response Diffs</option>
            </select>
            <select id="evidence-filter-backend" onchange="loadEvidenceGallery()" style="background: var(--zerok-bg-alt); color: var(--zerok-text); border: 1px solid var(--zerok-border); border-radius: 4px; padding: 4px 8px;">
                <option value="">All Backends</option>
                <option value="external">External (Antsle)</option>
                <option value="internal">Internal (Mini-PC)</option>
            </select>
            <select id="evidence-filter-mode" onchange="loadEvidenceGallery()" style="background: var(--zerok-bg-alt); color: var(--zerok-text); border: 1px solid var(--zerok-border); border-radius: 4px; padding: 4px 8px;">
                <option value="">All Modes</option>
                <option value="exploitable">Exploitable</option>
                <option value="observable">Observable</option>
            </select>
        </div>
    </div>
    <div id="evidence-stats-bar" style="display: flex; gap: 16px; margin-bottom: 16px; padding: 10px; background: var(--zerok-bg-alt); border-radius: 8px; font-size: 0.85em;"></div>
    <div id="evidence-gallery-grid" class="evidence-gallery-grid"></div>
    <div id="evidence-actions" style="display: flex; gap: 8px; margin-top: 16px; justify-content: flex-end;">
        <button onclick="downloadEvidenceManifest()" style="background: var(--zerok-bg-alt); color: var(--zerok-text); border: 1px solid var(--zerok-border); border-radius: 6px; padding: 8px 16px; cursor: pointer;">Generate Manifest</button>
        <button onclick="createEvidencePackage()" style="background: var(--zerok-primary); color: white; border: none; border-radius: 6px; padding: 8px 16px; cursor: pointer;">Package for Client</button>
    </div>
</div>
```

**Step 3: Add Evidence Gallery JavaScript**

```javascript
async function loadEvidenceGallery() {
    if (!currentEngagementId) return;

    const typeFilter = document.getElementById('evidence-filter-type')?.value || '';
    const backendFilter = document.getElementById('evidence-filter-backend')?.value || '';
    const modeFilter = document.getElementById('evidence-filter-mode')?.value || '';

    let url = `/api/artifacts?engagement_id=${currentEngagementId}`;
    if (typeFilter) url += `&type=${typeFilter}`;
    if (backendFilter) url += `&backend=${backendFilter}`;
    if (modeFilter) url += `&capture_mode=${modeFilter}`;

    // Load stats
    const statsResp = await fetch(`/api/evidence/stats?engagement_id=${currentEngagementId}`);
    const stats = await statsResp.json();
    renderEvidenceStats(stats);

    // Load artifacts
    const resp = await fetch(url);
    const data = await resp.json();
    renderEvidenceGalleryGrid(data.artifacts || []);
}

function renderEvidenceStats(stats) {
    const bar = document.getElementById('evidence-stats-bar');
    if (!bar) return;

    const sizeMB = ((stats.total_size_bytes || 0) / (1024 * 1024)).toFixed(1);
    bar.innerHTML = `
        <div><strong>${stats.total_artifacts || 0}</strong> <span style="color: var(--zerok-text-muted);">artifacts</span></div>
        <div><strong>${stats.coverage?.percent || 0}%</strong> <span style="color: var(--zerok-text-muted);">coverage</span>
            (${stats.coverage?.findings_with_evidence || 0}/${stats.coverage?.findings_total || 0} findings)</div>
        <div><strong>${sizeMB}</strong> <span style="color: var(--zerok-text-muted);">MB total</span></div>
        <div style="margin-left: auto; display: flex; gap: 8px;">
            ${Object.entries(stats.by_type || {}).map(([t, c]) => `<span style="color: var(--zerok-text-dim);">${t}: ${c}</span>`).join('')}
        </div>
    `;
}

function renderEvidenceGalleryGrid(artifacts) {
    const grid = document.getElementById('evidence-gallery-grid');
    if (!grid) return;

    if (artifacts.length === 0) {
        grid.innerHTML = '<div style="color: var(--zerok-text-dim); padding: 40px; text-align: center;">No evidence artifacts found. Evidence is captured automatically when the verify agent runs.</div>';
        return;
    }

    const severityColors = {
        critical: 'var(--zerok-critical)',
        high: 'var(--zerok-high)',
        medium: 'var(--zerok-medium)',
        low: 'var(--zerok-low)',
        info: 'var(--zerok-info)',
    };

    grid.innerHTML = artifacts.map(art => {
        const sevColor = severityColors[(art.severity || '').toLowerCase()] || 'var(--zerok-text-dim)';
        const isImage = art.type === 'screenshot';

        const preview = isImage
            ? `<img src="/api/artifacts/${art.id}/thumbnail" loading="lazy" style="width: 100%; aspect-ratio: 16/10; object-fit: cover; border-radius: 4px;">`
            : `<div style="display: flex; align-items: center; justify-content: center; min-height: 120px; background: var(--zerok-bg); border-radius: 4px; font-size: 2em;">
                ${{screenshot: '\u{1F4F7}', http_pair: '\u{1F4CB}', command_output: '\u{1F5A5}', tool_log: '\u{1F4C4}', response_diff: '\u{1F504}'}[art.type] || '\u{1F4CE}'}
               </div>`;

        return `
            <div class="gallery-card" onclick="showArtifactFullsize('${art.id}')" style="cursor: pointer;">
                ${preview}
                <div style="padding: 8px 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 0.8em; color: ${sevColor}; font-weight: 600; text-transform: uppercase;">${art.severity || ''}</span>
                        <span style="font-size: 0.7em; color: var(--zerok-text-dim);">${art.backend || ''}</span>
                    </div>
                    <div style="font-size: 0.85em; color: var(--zerok-text); margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        ${art.caption || art.type}
                    </div>
                    <div style="font-size: 0.7em; color: var(--zerok-text-dim); margin-top: 2px;">
                        ${art.finding_title ? art.finding_title.substring(0, 30) : art.finding_id || ''}
                    </div>
                </div>
            </div>`;
    }).join('');
}

async function downloadEvidenceManifest() {
    if (!currentEngagementId) return;
    const resp = await fetch(`/api/evidence/manifest?engagement_id=${currentEngagementId}`);
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentEngagementId}-evidence-manifest.json`;
    a.click();
    URL.revokeObjectURL(url);
}

async function createEvidencePackage() {
    if (!currentEngagementId) return;
    const resp = await fetch(`/api/evidence/package?engagement_id=${currentEngagementId}`, { method: 'POST' });
    const data = await resp.json();
    if (data.ok) {
        window.open(data.package.download_url, '_blank');
    }
}
```

**Step 4: Add Gallery CSS**

```css
.evidence-gallery-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
}

.gallery-card {
    background: var(--zerok-card);
    border: 1px solid var(--zerok-border);
    border-radius: 8px;
    padding: 10px;
    transition: border-color 0.2s, transform 0.15s;
}

.gallery-card:hover {
    border-color: var(--zerok-primary);
    transform: translateY(-2px);
}
```

**Step 5: Wire view switching**

In the existing `showView(viewName)` function, add `evidence-view` to the handled views. Also wire `loadEvidenceGallery()` to fire when the evidence view is shown:

Find the view switching logic and add:
```javascript
if (viewName === 'evidence') loadEvidenceGallery();
```

**Step 6: Verify in browser**

Navigate to dashboard, click "Evidence" in sidebar. Confirm:
- Stats bar shows totals
- Filter dropdowns work
- Gallery grid renders artifact cards
- Click card opens lightbox
- Manifest download works
- Package for Client generates ZIP

**Step 7: Commit**

```bash
git add tools/athena-dashboard/index.html
git commit -m "feat: Evidence Gallery page with filters, stats, manifest, and client packaging"
```

---

## Task 8: Update athena-verify Agent for Evidence Capture

**Files:**
- Modify: `.claude/agents/athena-verify.md`

**Step 1: Fix relationship direction**

Find all instances of `[:SUPPORTS]` and replace with `[:EVIDENCED_BY]` in the correct direction:

Change:
```cypher
MERGE (ep:EvidencePackage {id: $pkg_id})-[:SUPPORTS]->(f)
```
To:
```cypher
MERGE (f)-[:EVIDENCED_BY]->(ep)
```

**Step 2: Add evidence capture instructions**

Add a new section to the agent instructions after the EvidencePackage creation section:

```markdown
## Evidence Artifact Capture

After creating an EvidencePackage, capture supporting artifacts and upload to the dashboard:

### Screenshot Capture (via Playwright MCP or tool output)

For web-based findings:
1. Use Playwright MCP `browser_navigate` to visit the target URL
2. Use `browser_take_screenshot` to capture baseline state
3. If exploitable mode: replay the vulnerability, capture the result
4. If observable mode: capture the visible condition (error page, version disclosure, missing headers)

For CLI-based findings (nmap, testssl, etc.):
1. Save command output to a text file
2. If the tool produces visual output, capture a screenshot of the terminal

### Upload Each Artifact

```bash
curl -s -X POST http://localhost:8080/api/artifacts \
  -F "file=@/path/to/screenshot.png" \
  -F "finding_id=${finding_id}" \
  -F "engagement_id=${engagement_id}" \
  -F "type=screenshot" \
  -F "caption=Description of what is shown" \
  -F "agent=athena-verify" \
  -F "backend=${backend}" \
  -F "capture_mode=${capture_mode}"
```

Upload types:
- `screenshot` — PNG/JPEG visual evidence
- `http_pair` — Save request and response as separate .txt files
- `command_output` — Tool terminal output as .txt
- `tool_log` — Raw tool output (nmap XML, nikto JSON)
- `response_diff` — Diff between baseline and exploit response

### Capture Mode Selection

Read the engagement's evidence mode:
```cypher
MATCH (e:Engagement {id: $eid}) RETURN e.evidence_mode AS mode
```

- `exploitable` (default): Replay exploit, capture proof of success
- `observable`: Document the condition WITHOUT triggering the vulnerability

### Evidence Per Finding Checklist

For each verified finding, aim for 3+ evidence types:
1. [ ] At least 1 screenshot (baseline or condition)
2. [ ] HTTP request/response pair (for web findings)
3. [ ] Command output or tool log
4. [ ] Response diff (if baseline comparison was done)

Achieving 3+ evidence types = HIGH confidence.
```

**Step 3: Add evidence_mode to Engagement node**

In server.py, update the engagement creation endpoint to accept `evidence_mode`:

Find the Engagement creation Cypher and add `evidence_mode: $mode` property. Default to `exploitable`.

**Step 4: Verify**

Read the updated agent file and confirm:
- Relationship direction is `(f)-[:EVIDENCED_BY]->(ep)`
- Evidence capture instructions are clear
- Capture mode selection reads from Engagement node

**Step 5: Commit**

```bash
git add .claude/agents/athena-verify.md tools/athena-dashboard/server.py
git commit -m "feat: athena-verify agent evidence capture instructions + evidence_mode on Engagement"
```

---

## Task 9: Update athena-report Agent for Evidence Embedding

**Files:**
- Modify: `.claude/agents/athena-report.md`

**Step 1: Update Neo4j queries to include Artifacts**

Add this query to the report agent's data gathering section:

```cypher
MATCH (f:Finding {engagement_id: $eid})
OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
OPTIONAL MATCH (f)-[:HAS_ARTIFACT]->(a:Artifact)
WITH f, ep, collect(a {.id, .type, .caption, .file_path, .file_hash, .capture_mode}) AS artifacts
RETURN f.id AS id, f.title AS title, f.severity AS severity,
       f.target AS target, f.description AS description,
       f.cvss AS cvss, f.cve AS cve, f.evidence AS evidence,
       ep.confidence AS confidence, ep.verification_method AS method,
       ep.http_pairs AS http_pairs, ep.output_evidence AS output_evidence,
       artifacts
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 0 WHEN 'high' THEN 1
        WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
    END
```

**Step 2: Update report template to embed evidence inline**

Update the report markdown template for each finding to include:

```markdown
### {section}.{index} {title}

**Severity:** {severity} | **CVSS:** {cvss} | **Status:** Confirmed
**Target:** {target}
{if capture_mode == "observable": **Mode:** OBSERVABLE (vulnerability documented, not exploited — production system)}

**Description:**
{description}

**Evidence:**

{for each artifact where type == "screenshot":
![Figure {section}.{index}{letter} — {caption}]({file_path})
*SHA-256: {file_hash[:16]}...*
}

{if http_pairs:
**HTTP Request/Response:**
```
{http_pairs}
```
}

{if output_evidence:
**Command Output:**
```
{output_evidence}
```
}

**Confidence:** {confidence} ({artifact_count} evidence types)
**Verified by:** athena-verify | {timestamp}

**Remediation:**
{remediation}
```

**Step 3: Add manifest appendix generation**

At the end of the report, instruct the agent to:

```markdown
## Appendix A — Evidence Manifest

Query the manifest API and include the full artifact list:

```bash
curl -s http://localhost:8080/api/evidence/manifest?engagement_id=${engagement_id} > evidence-manifest.json
```

Summarize in a table:
| # | Finding | Type | Capture Mode | SHA-256 | Backend |
|---|---------|------|--------------|---------|---------|
{for each artifact in manifest}
```

**Step 4: Verify**

Read the updated agent file and confirm evidence embedding instructions are clear.

**Step 5: Commit**

```bash
git add .claude/agents/athena-report.md
git commit -m "feat: athena-report agent embeds evidence inline with auto-numbered figures"
```

---

## Task 10: Update Tool Registry

**Files:**
- Modify: `tools/athena-dashboard/tool-registry.json`

**Step 1: Add evidence_upload tool**

```json
"evidence_upload": {
    "display_name": "Evidence Artifact Upload",
    "endpoint": "/api/artifacts",
    "timeout": 30,
    "backends": ["external", "internal"],
    "category": "enrichment",
    "params": {
        "file": {"type": "file", "required": true, "description": "Evidence file (screenshot, log, etc.)"},
        "finding_id": {"type": "string", "required": true, "description": "Finding ID to link evidence to"},
        "engagement_id": {"type": "string", "required": true, "description": "Engagement ID"},
        "type": {"type": "string", "required": true, "description": "screenshot|http_pair|command_output|tool_log|response_diff"},
        "caption": {"type": "string", "required": false, "description": "Human-readable description"},
        "capture_mode": {"type": "string", "required": false, "default": "exploitable", "description": "exploitable|observable"}
    }
}
```

**Step 2: Add evidence_package tool**

```json
"evidence_package": {
    "display_name": "Client Evidence Package",
    "endpoint": "/api/evidence/package",
    "timeout": 60,
    "backends": ["external", "internal"],
    "category": "enrichment",
    "params": {
        "engagement_id": {"type": "string", "required": true, "description": "Engagement ID to package"}
    }
}
```

**Step 3: Verify**

```bash
python3 -c "import json; json.load(open('tools/athena-dashboard/tool-registry.json'))"
```

Expected: No errors (valid JSON).

**Step 4: Commit**

```bash
git add tools/athena-dashboard/tool-registry.json
git commit -m "feat: add evidence_upload and evidence_package to tool registry"
```

---

## Task 11: Add evidence_mode to Engagement Creation UI

**Files:**
- Modify: `tools/athena-dashboard/index.html`

**Step 1: Add evidence mode selector to new engagement form**

Find the engagement creation form/modal in the HTML. Add a dropdown:

```html
<label style="color: var(--zerok-text-muted); font-size: 0.85em;">Evidence Mode</label>
<select id="new-eng-evidence-mode" style="background: var(--zerok-bg-alt); color: var(--zerok-text); border: 1px solid var(--zerok-border); border-radius: 4px; padding: 6px 10px; width: 100%;">
    <option value="exploitable">Exploitable (lab/CTF — replay attacks)</option>
    <option value="observable">Observable (healthcare/production — document only)</option>
</select>
```

**Step 2: Wire the value into engagement creation**

Find the JavaScript that POSTs to `/api/engagements` and add `evidence_mode` to the payload:

```javascript
evidence_mode: document.getElementById('new-eng-evidence-mode')?.value || 'exploitable'
```

**Step 3: Show evidence mode in engagement details**

Where engagement details are displayed, add the mode badge:

```javascript
const modeBadge = eng.evidence_mode === 'observable'
    ? '<span style="color: var(--zerok-info); font-size: 0.8em; border: 1px solid var(--zerok-info); border-radius: 4px; padding: 2px 6px;">OBSERVABLE</span>'
    : '<span style="color: var(--zerok-low); font-size: 0.8em; border: 1px solid var(--zerok-low); border-radius: 4px; padding: 2px 6px;">EXPLOITABLE</span>';
```

**Step 4: Verify in browser**

Create a new engagement. Confirm the evidence mode dropdown appears and the selected value persists.

**Step 5: Commit**

```bash
git add tools/athena-dashboard/index.html tools/athena-dashboard/server.py
git commit -m "feat: evidence mode selector (exploitable/observable) on engagement creation"
```

---

## Task 12: Integration Test — End-to-End Evidence Flow

**Step 1: Start the server**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/pip install Pillow>=10.0.0
.venv/bin/uvicorn server:app --host 0.0.0.0 --port 8080 --reload
```

**Step 2: Create test engagement**

Via dashboard UI, create engagement with:
- Name: "Evidence Test"
- Evidence mode: "Exploitable"

**Step 3: Create test finding**

```bash
curl -s -X POST http://localhost:8080/api/findings \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQL Injection in Login Form",
    "severity": "critical",
    "category": "A03",
    "target": "http://test.local/login",
    "agent": "WV",
    "description": "Error-based SQL injection via username parameter",
    "evidence": "SQL error in response: Microsoft SQL Server",
    "engagement": "ENGAGEMENT_ID_HERE"
  }'
```

**Step 4: Upload test artifacts**

```bash
# Take a screenshot of anything for testing
screencapture /tmp/test-evidence.png

# Upload screenshot
curl -X POST http://localhost:8080/api/artifacts \
  -F "file=@/tmp/test-evidence.png" \
  -F "finding_id=FINDING_ID_HERE" \
  -F "engagement_id=ENGAGEMENT_ID_HERE" \
  -F "type=screenshot" \
  -F "caption=Login page with SQL error disclosure" \
  -F "agent=athena-verify" \
  -F "backend=external" \
  -F "capture_mode=exploitable"

# Upload command output
echo "sqlmap identified SQL injection in 'username' parameter" > /tmp/test-cmd.txt
curl -X POST http://localhost:8080/api/artifacts \
  -F "file=@/tmp/test-cmd.txt" \
  -F "finding_id=FINDING_ID_HERE" \
  -F "engagement_id=ENGAGEMENT_ID_HERE" \
  -F "type=command_output" \
  -F "caption=sqlmap confirmation output" \
  -F "agent=athena-verify" \
  -F "backend=external" \
  -F "capture_mode=exploitable"
```

**Step 5: Verify dashboard**

- [ ] Findings view: Expand finding → Evidence tab shows screenshot thumbnail + command output card
- [ ] Click screenshot → Lightbox opens with full-size image
- [ ] Evidence Gallery: Shows both artifacts with filters working
- [ ] Stats bar: Shows 2 artifacts, 100% coverage (1/1 finding)
- [ ] Generate Manifest: Downloads JSON with both artifacts, SHA-256 hashes
- [ ] Package for Client: Downloads ZIP with evidence + manifest

**Step 6: Verify Neo4j**

```bash
curl -s http://localhost:8080/api/artifacts?engagement_id=ENGAGEMENT_ID_HERE | python3 -m json.tool
```

Expected: 2 artifacts with correct metadata, file paths, hashes.

**Step 7: Final commit**

```bash
git add -A
git commit -m "test: end-to-end evidence capture integration verified"
```

---

## Summary of Commits

| # | Commit Message | Files |
|---|---------------|-------|
| 1 | `feat: evidence directory structure + Pillow dependency` | requirements.txt, server.py, start.sh |
| 2 | `feat: artifact upload endpoint with SHA-256 hashing and thumbnails` | server.py |
| 3 | `feat: artifact query, file serving, thumbnail, and delete endpoints` | server.py |
| 4 | `feat: evidence stats, manifest generation, and ZIP packaging endpoints` | server.py |
| 5 | `fix: evidence query supports both EvidencePackage and Artifact nodes` | server.py |
| 6 | `feat: enhanced evidence rendering with artifact grid, lightbox, and confidence display` | index.html |
| 7 | `feat: Evidence Gallery page with filters, stats, manifest, and client packaging` | index.html |
| 8 | `feat: athena-verify agent evidence capture instructions + evidence_mode on Engagement` | athena-verify.md, server.py |
| 9 | `feat: athena-report agent embeds evidence inline with auto-numbered figures` | athena-report.md |
| 10 | `feat: add evidence_upload and evidence_package to tool registry` | tool-registry.json |
| 11 | `feat: evidence mode selector (exploitable/observable) on engagement creation` | index.html, server.py |
| 12 | `test: end-to-end evidence capture integration verified` | — |
