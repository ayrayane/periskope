"""The DSOMM activities the catalog measures, from the bundled referential export."""
import json
from importlib.resources import files

from periskope_core.catalog import CHECKS
from periskope_core.models import Activity

REFERENTIAL_VERSION = "5.0.2"

ALL_ACTIVITIES: dict[str, Activity] = {
    a["name"]: Activity(**a)
    for a in json.loads(files("periskope_core").joinpath(f"data/dsomm-{REFERENTIAL_VERSION}.json").read_text())
}
ACTIVITIES: dict[str, Activity] = {c.activity: ALL_ACTIVITIES[c.activity] for c in CHECKS}
