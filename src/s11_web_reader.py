"""Web reader: paper/main.tex -> docs/paper/index.html (pandoc), served by GitHub Pages."""
import re, shutil, subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
paper, out = root / "paper", root / "docs/paper"
(out / "figures").mkdir(parents=True, exist_ok=True)

def flatten(path):
    """Inline \\input files and drop wrappers pandoc does not understand."""
    tex = path.read_text()
    def inc(m):
        p = paper / (m.group(1) if m.group(1).endswith(".tex") else m.group(1) + ".tex")
        return flatten(p)
    tex = re.sub(r"\\input\{([^}]+)\}", inc, tex)
    tex = re.sub(r"\\resizebox\{[^}]*\}\{!\}\{", r"{", tex)
    tex = re.sub(r"\{(fig\d+_\w+)\.pdf\}", r"{figures/\1.png}", tex)
    return tex

with tempfile.TemporaryDirectory() as tmp:
    src = Path(tmp) / "flat.tex"
    src.write_text(flatten(paper / "main.tex"))
    subprocess.run(["pandoc", str(src), "-f", "latex", "-t", "html5", "--standalone",
                    "--template", str(out / "template.html"), "--mathml", "--toc", "--toc-depth=2",
                    "--number-sections", "--citeproc", "--bibliography", str(paper / "refs.bib"),
                    "--metadata", "link-citations=true",
                    "--variable", "css=" + (out / "reader.css").read_text(),
                    "-o", str(out / "index.html")], check=True, cwd=paper)

for png in (root / "outputs/figures").glob("fig*.png"):
    shutil.copy(png, out / "figures" / png.name)
shutil.copy(root / "paper.pdf", out / "paper.pdf")
print(out / "index.html")
