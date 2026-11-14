"""Read-only measurement of one large repository, as Periskope reads it. Run it inside the collector pod of the instance:

    kubectl -n periskope exec -i deploy/periskope-collector-<instance> -- python - <groupe/projet> < docs/mesure-gros-depot.py

It lists the repository tree like an analysis does (same caps: 50 000 entries, 120 s), then runs every check once, and prints
how fast GitLab answered, what stopped the listing (the entry cap or the time) and how many files the checks could see.
Nothing is written anywhere: not in GitLab, not in Periskope's database."""
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote

from periskope_checks import REGISTRY, run_all
from periskope_checks.context import MAX_TREE_ENTRIES, MAX_TREE_SECONDS, Context
from periskope_clients.gitlab import GitLab


async def main(path: str) -> None:
    slug = os.environ["PERISKOPE_INSTANCE"]
    inst = next(i for i in json.loads(Path(os.environ["PERISKOPE_INSTANCES_FILE"]).read_text()) if i["slug"] == slug)
    gl = GitLab(inst["url"], Path(os.environ["PERISKOPE_SECRETS_DIR"]) / f"gitlab-token-{slug}" / "token", verify=inst.get("ca_file") or True)
    meta = await gl.get(f"/projects/{quote(path, safe='')}")
    if meta is None:
        sys.exit(f"{path} : projet introuvable avec le jeton de service")
    branch = meta["default_branch"]
    sha = (await gl.get(f"/projects/{meta['id']}/repository/branches/{quote(branch, safe='')}"))["commit"]["id"]
    ctx = Context(gl, path, meta["id"], branch, sha, enterprise=inst.get("enterprise", True))
    t0, calls = time.monotonic(), gl.calls
    tree = await ctx.tree()
    listing = time.monotonic() - t0
    pages = gl.calls - calls
    t1 = time.monotonic()
    outcomes = await run_all(ctx, list(REGISTRY))
    print(json.dumps({
        "projet": path, "branche": branch,
        "liste_secondes": round(listing, 1), "pages": pages, "secondes_par_page": round(listing / max(pages, 1), 2),
        "entrees_lues": tree.entries if tree else None, "fichiers_lus": len(tree.paths) if tree else None,
        "coupee": tree.truncated if tree else None,
        "arret": None if not tree or not tree.truncated else ("plafond d'entrées" if tree.entries >= MAX_TREE_ENTRIES else f"{MAX_TREE_SECONDS} s"),
        "analyse_secondes": round(time.monotonic() - t1 + listing, 1), "appels_gitlab": gl.calls - calls,
        "preuves_depot": {k: o.status.value for k, o in outcomes.items() if k.startswith("repo.")},
    }, ensure_ascii=False, indent=2))
    await gl.aclose()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage : python - <groupe/projet> < docs/mesure-gros-depot.py")
    asyncio.run(main(sys.argv[1]))
