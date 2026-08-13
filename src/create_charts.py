import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = json.loads((ROOT / "results" / "summary.json").read_text())
ASSETS = ROOT / "assets"; ASSETS.mkdir(exist_ok=True)


def chart(path, title, subtitle, labels, values, colors):
    w, h, left, top, cw, ch = 1100, 600, 130, 120, 850, 350
    maximum = max(values + [1]) * 1.2
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
           '<rect width="100%" height="100%" fill="#F8FAFC"/>',
           f'<text x="{left}" y="48" font-family="Arial" font-size="29" font-weight="700" fill="#172B4D">{title}</text>',
           f'<text x="{left}" y="80" font-family="Arial" font-size="16" fill="#5E6C84">{subtitle}</text>']
    gap=cw/len(values); bw=gap*.5
    for i,(label,value) in enumerate(zip(labels,values)):
        x=left+i*gap+(gap-bw)/2; bh=ch*value/maximum; y=top+ch-bh
        out += [f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="5" fill="{colors[i]}"/>',
                f'<text x="{x+bw/2}" y="{y-10}" text-anchor="middle" font-family="Arial" font-size="18" font-weight="700">{value}</text>',
                f'<text x="{x+bw/2}" y="{top+ch+32}" text-anchor="middle" font-family="Arial" font-size="16">{label}</text>']
    out.append('</svg>'); path.write_text("\n".join(out))


chart(ASSETS / "dependency_surface.svg", "Resolved dependency surface",
      "Three pinned inputs expand to twelve packages in the captured pip resolution",
      ["Direct pinned", "Transitive selected"],
      [SUMMARY["direct_pinned_packages"], SUMMARY["transitive_resolver_selected_packages"]], ["#005B96", "#F28E2B"])
chart(ASSETS / "osv_coverage.svg", "Exact-version OSV query outcome",
      "A clean database query is time-bound evidence, not proof that vulnerabilities do not exist",
      ["Queried versions", "Versions with matches"],
      [SUMMARY["resolved_packages"], SUMMARY["packages_with_osv_matches"]], ["#2A9D8F", "#D1495B"])
print("created 2 SVG charts")
