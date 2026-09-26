"""Self-contained HTML report: one file, no external assets, no network fetches.

Everything (CSS, JS) is inlined so the report can be emailed or attached to a
ticket and still render offline.
"""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING, Any

from ..config import TOOL_NAME, VERSION

if TYPE_CHECKING:  # pragma: no cover
    from ..models import Report
    from . import Bundle

SEVERITIES = ("critical", "high", "medium", "low", "info")

CSS = """
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;
 font:14px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:#58a6ff}
.wrap{max-width:1120px;margin:0 auto;padding:32px 24px 96px}
header.top{border-bottom:1px solid #30363d;padding-bottom:20px;margin-bottom:28px}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
h2{font-size:16px;margin:36px 0 12px;padding-bottom:8px;border-bottom:1px solid #21262d}
h3{font-size:14px;margin:22px 0 8px;color:#e6edf3}
.sub{color:#8b949e;font-size:13px}
.sub code{background:#161b22;padding:1px 5px;border-radius:4px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin:22px 0 8px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 16px}
.card .n{font-size:26px;font-weight:600;line-height:1.1}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:#8b949e;margin-top:4px}
.sev{font-weight:600}
.critical{color:#ff7b72}.high{color:#ffa657}.medium{color:#e3b341}.low{color:#79c0ff}.info{color:#56d364}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap}
tbody tr:hover{background:#161b22}
td.mono,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:700;
 letter-spacing:.06em;color:#0d1117}
.badge.critical{background:#ff7b72}.badge.high{background:#ffa657}.badge.medium{background:#e3b341}
.badge.low{background:#79c0ff}.badge.info{background:#56d364}
.finding{border:1px solid #30363d;border-left-width:3px;border-radius:6px;padding:12px 14px;margin:10px 0;background:#161b22}
.finding.critical{border-left-color:#ff7b72}
.finding.high{border-left-color:#ffa657}
.finding.medium{border-left-color:#e3b341}
.finding.low{border-left-color:#79c0ff}
.finding.info{border-left-color:#56d364}
.finding .t{font-weight:600;color:#e6edf3;margin-bottom:2px}
.finding .c{color:#8b949e;font-size:11.5px;font-family:ui-monospace,Menlo,monospace}
.finding p{margin:7px 0 0;color:#b9c2cc}
.finding .fix{color:#7ee787;font-size:12.5px}
.finding .fix b{color:#56d364}
.filters{display:flex;gap:7px;flex-wrap:wrap;margin:14px 0}
.filters button{background:#161b22;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;
 padding:5px 12px;font-size:12px;cursor:pointer;font-family:inherit}
.filters button:hover{border-color:#58a6ff;color:#58a6ff}
.filters button.on{background:#21262d;border-color:#58a6ff;color:#58a6ff}
.hidden{display:none}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;overflow-x:auto;
 font-size:12px;color:#b9c2cc}
footer{margin-top:44px;padding-top:16px;border-top:1px solid #21262d;color:#6e7681;font-size:12px}
.empty{color:#56d364;padding:10px 0}
details>summary{cursor:pointer;color:#8b949e;font-size:12.5px;padding:6px 0;user-select:none}
details>summary:hover{color:#58a6ff}
"""

JS = """
(function(){
  var btns=document.querySelectorAll('.filters button[data-sev]');
  btns.forEach(function(b){
    b.addEventListener('click',function(){
      var on=b.classList.contains('on');
      btns.forEach(function(x){x.classList.remove('on')});
      if(!on){b.classList.add('on')}
      var sev=on?null:b.getAttribute('data-sev');
      document.querySelectorAll('.finding').forEach(function(el){
        el.classList.toggle('hidden',!!sev&&el.getAttribute('data-sev')!==sev);
      });
      document.querySelectorAll('tr[data-sev]').forEach(function(el){
        el.classList.toggle('hidden',!!sev&&el.getAttribute('data-sev')!==sev);
      });
    });
  });
  var t=document.getElementById('theme');
  if(t){t.addEventListener('click',function(){
    document.body.classList.toggle('light');
    t.textContent=document.body.classList.contains('light')?'Dark theme':'Light theme';
  })}
})();
"""

LIGHT_CSS = """
body.light{background:#ffffff;color:#24292f}
body.light h3,body.light .finding .t{color:#0d1117}
body.light .card,body.light .finding,body.light tbody tr:hover,body.light pre{background:#f6f8fa}
body.light .card,body.light .finding,body.light th,body.light td{border-color:#d0d7de}
body.light th,body.light .sub,body.light .finding .c{color:#57606a}
body.light footer{border-color:#d0d7de;color:#6e7781}
body.light .badge{color:#ffffff}
body.light .finding .fix{color:#116329}
"""


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-") or "x"


def render_html(bundle: Bundle) -> str:
    counts = bundle.counts
    total = len(bundle.findings)
    parts: list[str] = []

    parts.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    parts.append('<meta name=viewport content="width=device-width,initial-scale=1">')
    parts.append(f"<title>{_e(TOOL_NAME)} report - {_e(bundle.command)}</title>")
    parts.append(f"<style>{CSS}{LIGHT_CSS}</style></head><body><div class=wrap>")

    parts.append("<header class=top>")
    parts.append(f"<h1>{_e(TOOL_NAME)} <span class=sub>v{_e(VERSION)}</span></h1>")
    parts.append(
        f"<div class=sub>command <code>{_e(bundle.command)}</code>"
        f" &middot; {total} finding(s) &middot; highest severity "
        f'<span class="sev {_e(bundle.severity)}">{_e(bundle.severity.upper())}</span>'
        f" &middot; {_e(bundle.started_at)}</div>"
    )
    parts.append("</header>")

    parts.append("<div class=cards>")
    parts.append(
        f'<div class=card><div class="n sev critical">{counts["critical"]}</div><div class=k>critical</div></div>'
    )
    parts.append(
        f'<div class=card><div class="n sev high">{counts["high"]}</div><div class=k>high</div></div>'
    )
    parts.append(
        f'<div class=card><div class="n sev medium">{counts["medium"]}</div><div class=k>medium</div></div>'
    )
    parts.append(f'<div class=card><div class="n sev low">{counts["low"]}</div><div class=k>low</div></div>')
    parts.append(
        f'<div class=card><div class="n sev info">{counts["info"]}</div><div class=k>info</div></div>'
    )
    parts.append(
        f'<div class=card><div class="n">{len(bundle.reports)}</div><div class=k>modules</div></div>'
    )
    parts.append("</div>")

    if bundle.findings:
        buttons = ["<div class=filters>"]
        for severity in SEVERITIES:
            if counts[severity]:
                buttons.append(f'<button data-sev="{severity}">{severity} ({counts[severity]})</button>')
        buttons.append("</div>")
        parts.append("".join(buttons))

    for report in bundle.reports:
        parts.append(_module_section(report))

    parts.append("<footer>")
    parts.append(
        f"Generated by {_e(TOOL_NAME)} v{_e(VERSION)}. "
        "For authorised security testing and education only. "
        "This report is self-contained and makes no external requests."
    )
    parts.append("</footer>")
    parts.append("</div>")
    parts.append(f"<script>{JS}</script></body></html>")
    return "".join(parts)


def _module_section(report: Report) -> str:
    anchor = _slug(report.module)
    out: list[str] = [f'<section id="{anchor}">']
    out.append(
        f"<h2>{_e(report.module)} <span class=sub>target {_e(report.target)} "
        f"&middot; {len(report.findings)} finding(s) &middot; {report.duration_seconds:.2f}s</span></h2>"
    )

    findings = report.sorted_findings()
    if findings:
        for finding in findings:
            out.append(
                f'<div class="finding {_e(finding.severity)}" data-sev="{_e(finding.severity)}">'
                f"<div class=t>{_e(finding.title)}</div>"
                f"<div class=c>{_e(finding.check)}</div>"
            )
            if finding.detail:
                out.append(f"<p>{_e(finding.detail)}</p>")
            if finding.remediation:
                out.append(f"<p class=fix><b>Fix:</b> {_e(finding.remediation)}</p>")
            if finding.evidence:
                pairs = " &middot; ".join(
                    f"{_e(k)}: <span class=mono>{_e(v)}</span>" for k, v in finding.evidence.items()
                )
                out.append(f"<p class=fix><b>Evidence:</b> {pairs}</p>")
            out.append("</div>")
    else:
        out.append("<div class=empty>No findings in this module.</div>")

    if report.data:
        out.append("<details><summary>Raw data</summary>")
        out.append(_data_table(report.data))
        out.append("</details>")

    out.append("</section>")
    return "".join(out)


def _data_table(data: dict[str, Any]) -> str:
    rows: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                rows.append(
                    f"<tr><td class=mono>{_e(key)}.{_e(sub_key)}</td><td class=mono>{_e(sub_value)}</td></tr>"
                )
        elif isinstance(value, (list, tuple)):
            rows.append(f"<tr><td class=mono>{_e(key)}</td><td class=mono>{len(value)} item(s)</td></tr>")
            for item in value[:50]:
                rows.append(
                    f"<tr><td class=mono>&nbsp;&nbsp;-</td><td class=mono>{_e(_item_text(item))}</td></tr>"
                )
        else:
            rows.append(f"<tr><td class=mono>{_e(key)}</td><td class=mono>{_e(value)}</td></tr>")

    body = "".join(rows) or "<tr><td colspan=2>empty</td></tr>"
    return f"<table><thead><tr><th>field</th><th>value</th></tr></thead><tbody>{body}</tbody></table>"


def _item_text(item: object) -> str:
    if isinstance(item, dict):
        parts = [f"{k}={v}" for k, v in item.items() if not isinstance(v, (list, dict))]
        return ", ".join(parts) or json.dumps(item, default=str)[:160]
    if isinstance(item, (list, tuple)):
        return ", ".join(str(x) for x in item)
    return str(item)
