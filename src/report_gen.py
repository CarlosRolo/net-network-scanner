import os
from datetime import datetime
from src.models import ScanResult

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; }
.header { background: #161b22; border-bottom: 1px solid #30363d; padding: 24px 40px; }
.header h1 { font-size: 22px; font-weight: 600; color: #58a6ff; }
.header p  { font-size: 13px; color: #8b949e; margin-top: 4px; }
.stats { display: flex; gap: 16px; padding: 24px 40px; flex-wrap: wrap; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; min-width: 140px; }
.stat-card .num { font-size: 28px; font-weight: 600; color: #58a6ff; }
.stat-card .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
.controls { padding: 0 40px 16px; }
.controls input { background: #161b22; border: 1px solid #30363d; color: #e6edf3; padding: 8px 14px; border-radius: 6px; font-size: 13px; width: 260px; }
.controls input::placeholder { color: #484f58; }
.host-block { margin: 0 40px 24px; background: #161b22; border: 1px solid #30363d; border-radius: 10px; overflow: hidden; }
.host-header { padding: 14px 20px; background: #1c2128; display: flex; align-items: center; cursor: pointer; user-select: none; justify-content: space-between; }
.host-header:hover { background: #21262d; }
.host-ip { font-size: 15px; font-weight: 600; color: #58a6ff; }
.host-meta { font-size: 12px; color: #8b949e; }
.badge { font-size: 11px; padding: 2px 10px; border-radius: 20px; font-weight: 500; margin-left: 10px; }
.badge-alive { background: #1a3a2a; color: #3fb950; }
.chevron { color: #8b949e; font-size: 18px; transition: transform .2s; }
.chevron.open { transform: rotate(180deg); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { padding: 10px 16px; text-align: left; color: #8b949e; font-weight: 500; border-bottom: 1px solid #30363d; }
td { padding: 10px 16px; border-bottom: 1px solid #21262d; }
tr:last-child td { border-bottom: none; }
.state-open { color: #3fb950; font-weight: 500; }
.state-closed { color: #484f58; }
.state-filtered { color: #d29922; }
.banner-cell { font-family: monospace; font-size: 11px; color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.footer { padding: 24px 40px; text-align: center; font-size: 12px; color: #484f58; }
.no-results { padding: 40px; text-align: center; color: #484f58; }
"""

JS = """
function toggleHost(id) {
  var body = document.getElementById('body-' + id);
  var chev = document.getElementById('chev-' + id);
  var visible = body.style.display !== 'none';
  body.style.display = visible ? 'none' : 'block';
  if (visible) { chev.classList.remove('open'); } else { chev.classList.add('open'); }
}
function filterHosts() {
  var q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.host-block').forEach(function(b) {
    b.style.display = b.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
  });
}
document.querySelectorAll('.host-block').forEach(function(b, i) {
  var body = document.getElementById('body-' + i);
  if (body) body.style.display = i === 0 ? 'block' : 'none';
});
"""

def _render_hosts(result: ScanResult) -> str:
    if not result.alive_hosts:
        return '<div class="no-results">No alive hosts found.</div>'

    blocks = []
    for idx, host in enumerate(result.alive_hosts):
        open_ports = [p for p in host.ports if p.state == "open"]
        meta_parts = []
        if host.hostname:
            meta_parts.append(host.hostname)
        if host.mac:
            meta_parts.append("MAC: " + host.mac)
        meta_parts.append(str(len(open_ports)) + " open port(s)")
        meta = " &nbsp;|&nbsp; ".join(meta_parts)

        rows = ""
        for svc in host.ports:
            banner_display = (svc.banner[:120] + "...") if len(svc.banner) > 120 else svc.banner
            rows += (
                "<tr>"
                "<td>" + str(svc.port) + "</td>"
                "<td>" + svc.protocol + "</td>"
                "<td class=\"state-" + svc.state + "\">" + svc.state + "</td>"
                "<td>" + svc.service + "</td>"
                "<td>" + svc.version + "</td>"
                "<td class=\"banner-cell\" title=\"" + svc.banner + "\">" + banner_display + "</td>"
                "</tr>"
            )

        blocks.append(
            "<div class=\"host-block\" data-ip=\"" + host.ip + "\">"
            "<div class=\"host-header\" onclick=\"toggleHost(" + str(idx) + ")\">"
            "<div style=\"display:flex;align-items:center\">"
            "<span class=\"host-ip\">" + host.ip + "</span>"
            "<span class=\"badge badge-alive\">alive</span>"
            "<span class=\"host-meta\" style=\"margin-left:12px\">" + meta + "</span>"
            "</div>"
            "<span class=\"chevron\" id=\"chev-" + str(idx) + "\">&#x25BE;</span>"
            "</div>"
            "<div id=\"body-" + str(idx) + "\">"
            "<table><thead><tr>"
            "<th>Port</th><th>Proto</th><th>State</th>"
            "<th>Service</th><th>Version</th><th>Banner</th>"
            "</tr></thead><tbody>" + rows + "</tbody></table>"
            "</div></div>"
        )
    return "\n".join(blocks)


def generate_report(result: ScanResult, output_dir: str = "reports/output") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "scan_" + timestamp + ".html"
    filepath = os.path.join(output_dir, filename)

    duration = ""
    if result.end_time:
        duration = str(round((result.end_time - result.start_time).total_seconds(), 1))

    hosts_html = _render_hosts(result)

    html = (
        "<!DOCTYPE html><html lang=\"es\"><head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Network Scan Report</title>"
        "<style>" + CSS + "</style></head><body>"
        "<div class=\"header\">"
        "<h1>&#x1F50D; Network Scan Report</h1>"
        "<p>Target: <strong>" + result.target + "</strong> &nbsp;|&nbsp; "
        "Started: " + result.start_time.strftime("%Y-%m-%d %H:%M:%S") + " &nbsp;|&nbsp; "
        "Duration: " + duration + "s</p>"
        "</div>"
        "<div class=\"stats\">"
        "<div class=\"stat-card\"><div class=\"num\">" + str(len(result.hosts)) + "</div><div class=\"label\">Hosts scanned</div></div>"
        "<div class=\"stat-card\"><div class=\"num\">" + str(len(result.alive_hosts)) + "</div><div class=\"label\">Alive hosts</div></div>"
        "<div class=\"stat-card\"><div class=\"num\">" + str(result.total_open_ports) + "</div><div class=\"label\">Open ports</div></div>"
        "<div class=\"stat-card\"><div class=\"num\">" + duration + "</div><div class=\"label\">Seconds</div></div>"
        "</div>"
        "<div class=\"controls\">"
        "<input type=\"text\" id=\"search\" placeholder=\"Filter by IP, hostname or service...\" oninput=\"filterHosts()\">"
        "</div>"
        "<div id=\"hosts-container\">" + hosts_html + "</div>"
        "<div class=\"footer\">Generated by net-network-scanner &nbsp;|&nbsp; github.com/CarlosRolo</div>"
        "<script>" + JS + "</script>"
        "</body></html>"
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print("[+] Report saved: " + filepath)
    return filepath
