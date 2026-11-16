from periskope_api.app import cell


def test_spreadsheet_formulas_from_gitlab_text_are_neutralised():
    assert cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    assert [cell(v) for v in ("+1", "-1", "@SUM(A1)", "\tx")] == ["'+1", "'-1", "'@SUM(A1)", "'\tx"]
    assert cell("team-a/flask") == "team-a/flask" and cell(None) == "" and cell(42.5) == "42.5"
