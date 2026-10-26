package layerscope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
)

func JSON(value any) ([]byte, error) {
	b, e := json.MarshalIndent(value, "", "  ")
	return append(b, '\n'), e
}

func Text(r *Report) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Rudy LayerScope %s\nManifest: %s\nPlatform: %s | default user: %q\nIntegrity: verified descriptors + DiffIDs (not signature authentication)\n", Version, r.ManifestDigest, r.Platform.String(), r.User)
	fmt.Fprintf(&b, "%d layers | %d final entries | %d revisions | %d hidden revisions\nPayload: %d bytes | hidden revisions: %d bytes (not compressed reclaimable size)\n", len(r.Layers), r.Summary.FinalEntries, r.Summary.FileRevisions, r.Summary.HiddenRevisions, r.Summary.PayloadBytes, r.Summary.HiddenPayloadBytes)
	for _, l := range r.Layers {
		fmt.Fprintf(&b, "Layer %d: %s | %d entries | %d whiteouts | %d expanded bytes\n", l.Number, l.Digest, l.Entries, len(l.Whiteouts), l.ExpandedBytes)
	}
	fmt.Fprintf(&b, "\n%d findings (heuristics for source review):\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%s %-7s layer=%d path=%q hidden=%t\n  %s\n", f.Rule, f.Level, f.Layer, f.Path, f.Hidden, f.Message)
	}
	return b.Bytes()
}

func DeltaText(d Delta) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Rudy LayerScope delta\nBefore: %s\nAfter:  %s\n%d filesystem changes | %d added findings | %d removed findings\n", d.Before, d.After, len(d.Changes), len(d.AddedFindings), len(d.RemovedFindings))
	for _, c := range d.Changes {
		fmt.Fprintf(&b, "%-8s %q\n", c.Kind, c.Path)
	}
	for _, f := range d.AddedFindings {
		fmt.Fprintf(&b, "+ %s %q\n", f.Rule, f.Path)
	}
	for _, f := range d.RemovedFindings {
		fmt.Fprintf(&b, "- %s %q\n", f.Rule, f.Path)
	}
	return b.Bytes()
}

func SARIF(r *Report) ([]byte, error) {
	toolRules := []any{}
	results := []any{}
	for _, rule := range Rules {
		toolRules = append(toolRules, map[string]any{"id": rule.ID, "name": rule.Name, "shortDescription": map[string]string{"text": rule.Description}})
	}
	for _, f := range r.Findings {
		location := map[string]any{"logicalLocations": []any{map[string]string{"name": f.Path, "fullyQualifiedName": r.ManifestDigest + ":" + f.Path, "kind": "resource"}}}
		result := map[string]any{"ruleId": f.Rule, "level": f.Level, "message": map[string]string{"text": f.Message}, "partialFingerprints": map[string]string{"rudyLayerScope/v1": f.Fingerprint}, "properties": map[string]any{"layer": f.Layer, "hidden": f.Hidden, "manifest": r.ManifestDigest}}
		if f.Path != "" {
			result["locations"] = []any{location}
		}
		results = append(results, result)
	}
	return JSON(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Rudy LayerScope", "version": Version, "informationUri": "https://github.com/r4venrudy/rudy-layerscope", "rules": toolRules}}, "results": results, "properties": map[string]any{"integrityVerified": r.IntegrityVerified, "authentication": "not verified", "manifest": r.ManifestDigest}}}})
}

// HTML is entirely self-contained. html/template escapes all attacker-controlled
// metadata, and the only script filters already-rendered text with textContent.
func HTML(r *Report) ([]byte, error) {
	t, err := template.New("report").Funcs(template.FuncMap{"octal": func(v int64) string { return fmt.Sprintf("%04o", v) }, "removed": func(v *int) string {
		if v == nil {
			return "final"
		}
		return "hidden at L" + strconv.Itoa(*v)
	}}).Parse(htmlReport)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = t.Execute(&b, r)
	return b.Bytes(), err
}

const htmlReport = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Rudy LayerScope investigation</title>
<style>:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1118;color:#e8f1f8}body{max-width:1240px;margin:40px auto;padding:0 24px}header{border-left:4px solid #55e0b6;padding:8px 28px 20px;background:linear-gradient(115deg,#101e2a,#0b1118)}.eyebrow{color:#55e0b6;letter-spacing:.2em;font:12px monospace}h1{font-size:48px;margin:16px 0}h2{font-size:24px;margin-top:38px}p{color:#a8bfd2;line-height:1.6}.digest{font:12px monospace;overflow-wrap:anywhere}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:28px 0}.stat{background:#101e2a;border:1px solid #254052;border-radius:10px;padding:20px}.stat strong{font-size:30px;display:block;color:#55e0b6}.stat span{font-size:12px;color:#a8bfd2}article{padding:15px 20px;margin:10px 0;border:1px solid #254052;border-radius:8px;background:#101923}article.error{border-left:3px solid #ff8b95}article.warning{border-left:3px solid #e8c775}code{color:#b5e9dd;overflow-wrap:anywhere}.pill{font:11px monospace;padding:5px 8px;background:#24353f;border-radius:4px}input{width:min(600px,90%);padding:13px;border:1px solid #355268;border-radius:6px;background:#101e2a;color:#f0f6fc;margin:8px 0 18px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;border-bottom:1px solid #213440;padding:12px 8px;vertical-align:top}td:first-child{max-width:460px;overflow-wrap:anywhere}th{color:#8fafc5}summary{cursor:pointer;color:#55e0b6;padding:15px 0}.scroll{overflow:auto}footer{border-top:1px solid #254052;margin-top:36px;padding:22px 0;font-size:12px;color:#8fafc5}@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}h1{font-size:34px}body{padding:0 14px}}</style>
<header><div class="eyebrow">RUDY SYSTEMS / OCI LAYER FORENSICS</div><h1>Rudy LayerScope</h1><p>See what the final filesystem hides.</p><div class="digest">{{.ManifestDigest}}</div><p>{{.Platform.String}} · User: {{printf "%q" .User}} · Integrity verified</p></header>
<div class="stats"><div class="stat"><strong>{{len .Layers}}</strong><span>VERIFIED LAYERS</span></div><div class="stat"><strong>{{.Summary.FinalEntries}}</strong><span>FINAL ENTRIES</span></div><div class="stat"><strong>{{.Summary.HiddenRevisions}}</strong><span>HIDDEN REVISIONS</span></div><div class="stat"><strong>{{len .Findings}}</strong><span>REVIEW FINDINGS</span></div></div>
<p>Digests establish content integrity, not publisher identity. Findings are review indicators; this report does not prove exploitability or runtime privileges. File bodies, environment values and build commands are omitted.</p>
<h2>Review findings</h2>{{range .Findings}}<article class="{{.Level}}"><span class="pill">{{.Rule}} / {{.Level}}</span> <code>{{.Path}}</code><p>{{.Message}}</p><small>Layer {{.Layer}}{{if .Hidden}} · hidden revision{{end}}</small></article>{{else}}<p>No configured rules matched. This is not proof that the image is safe.</p>{{end}}
<h2>Layer chain</h2>{{range .Layers}}<details><summary>Layer {{.Number}} · {{.Entries}} entries · {{len .Whiteouts}} whiteouts</summary><p class="digest">Blob: {{.Digest}}<br>DiffID: {{.DiffID}}<br>ChainID: {{.ChainID}}</p><p>{{.CompressedBytes}} stored bytes / {{.ExpandedBytes}} expanded bytes / {{.PayloadBytes}} payload bytes</p>{{range .Whiteouts}}<p><code>{{.}}</code></p>{{end}}</details>{{end}}
<h2>File revision timeline</h2><label for="filter">Filter by path, state, digest or mode</label><br><input id="filter" placeholder="e.g. .env, hidden, 4755"><div class="scroll"><table id="timeline"><thead><tr><th>Path</th><th>Layer</th><th>State</th><th>Type / mode</th><th>Evidence</th></tr></thead><tbody>{{range .History}}<tr><td><code>{{.Path}}</code></td><td>L{{.Layer}}</td><td>{{removed .RemovedBy}}<br>{{.Removal}}</td><td>{{.Kind}} / {{octal .Mode}}</td><td class="digest">{{.Digest}}{{if .Link}}<br>Link: {{.Link}}{{end}}</td></tr>{{end}}</tbody></table></div>
<footer>Rudy LayerScope {{.ToolVersion}} · offline preview · payload bytes: {{.Summary.PayloadBytes}}, hidden revision bytes: {{.Summary.HiddenPayloadBytes}}. Counts are logical revision sizes, not reclaimable compressed bytes. Implicit directories appear in JSON final files.</footer>
<script>document.getElementById('filter').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('#timeline tbody tr').forEach(row=>{row.hidden=!row.textContent.toLowerCase().includes(q)})});</script></html>`
