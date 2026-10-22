from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


ROLES = ("maintainer", "owner", "supporter", "securitymanager")
ALERT_JOB_NAME = "Vulnerability_Management_JIRA"
ALERT_SEPARATOR = "---------------------------"
CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.ASCII)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def plain(value):
    return "" if value is None else str(value)


def paragraph(value):
    value = plain(value)
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": value}] if value else [],
    }


def linked_paragraph(label, url):
    return {
        "type": "paragraph",
        "content": [
            {
                "type": "text",
                "text": label,
                "marks": [{"type": "link", "attrs": {"href": url}}],
            },
        ],
    }


def heading(value):
    return {
        "type": "heading",
        "attrs": {"level": 2},
        "content": [{"type": "text", "text": value}],
    }


def adf_table(headers, rows):
    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
        "content": [
            {
                "type": "tableRow",
                "content": [
                    {
                        "type": "tableHeader" if index == 0 else "tableCell",
                        "attrs": {},
                        "content": [paragraph(value)],
                    }
                    for value in row
                ],
            }
            for index, row in enumerate([headers, *rows])
        ],
    }


def valid_url(value):
    if not isinstance(value, str):
        raise RuntimeError("Product evidence link must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or any(ord(character) < 32 for character in value)
    ):
        raise RuntimeError("Invalid product evidence link")
    return value


def wiki_text(value):
    return re.sub(r"[{}\[\]|*]", " ", " ".join(plain(value).splitlines()))


def wiki_link(label, url):
    return (
        f"[{wiki_text(label)}|"
        + url.replace("[", "%5B").replace("]", "%5D").replace("|", "%7C")
        + "]"
    )


def reported_vectors(rows):
    return sorted({
        value.strip()
        for row in rows
        for value in row["evidence"]["cvss_vectors"].values()
        if isinstance(value, str) and value.strip()
    })


def alert_project_links(first):
    project = first.get("product")
    version = first.get("product_version")
    if (
        not isinstance(project, str)
        or not project.strip()
        or any(ord(character) < 32 for character in project)
        or not isinstance(version, str)
        or not version.strip()
        or any(ord(character) < 32 for character in version)
    ):
        raise RuntimeError("Product alert header requires project and version names")

    version_href = valid_url(first.get("product_href"))
    parsed = urlsplit(version_href)
    match = re.fullmatch(
        r"(/api/projects/[^/]+)/versions/[^/]+",
        parsed.path,
    )
    if match is None or parsed.query or parsed.fragment:
        raise RuntimeError(
            "Product alert header requires a Black Duck project-version URL"
        )
    project_href = urlunsplit(
        (parsed.scheme, parsed.netloc, match.group(1), "", "")
    )
    return project, project_href, version, version_href


def alert_adf_paragraph(label, value, href=None, *, bold_value=False):
    marks = []
    if bold_value:
        marks.append({"type": "strong"})
    if href is not None:
        marks.append({"type": "link", "attrs": {"href": href}})
    return {
        "type": "paragraph",
        "content": [
            {
                "type": "text",
                "text": label + " ",
                "marks": [{"type": "strong"}],
            },
            {
                "type": "text",
                "text": value,
                **({"marks": marks} if marks else {}),
            },
        ],
    }


def alert_adf_header(first):
    project, project_href, version, version_href = alert_project_links(first)
    return [
        alert_adf_paragraph("Job name:", ALERT_JOB_NAME, bold_value=True),
        alert_adf_paragraph("Project:", project, project_href),
        alert_adf_paragraph("Project Version:", version, version_href),
        paragraph(ALERT_SEPARATOR),
    ]


def alert_wiki_header(first):
    project, project_href, version, version_href = alert_project_links(first)
    return [
        f"*Job name:* *{ALERT_JOB_NAME}*",
        f"*Project:* [{wiki_text(project)}|{project_href}]",
        f"*Project Version:* [{wiki_text(version)}|{version_href}]",
        ALERT_SEPARATOR,
        "",
    ]


def render_product_epic_create_description(node, rows, description_format):
    """Render new product-reporting Epics using only qualified Task evidence."""
    context = node.get("context")
    if node.get("node_type") != "epic" or not isinstance(context, dict):
        raise RuntimeError("Expected a product vulnerability Epic")
    vulnerability = context.get("vulnerability")
    if not isinstance(vulnerability, str) or not vulnerability.strip():
        raise RuntimeError("Product Epic has no advisory identity")
    if not isinstance(rows, list) or not rows or any(
        not isinstance(row, dict) or row.get("vulnerability") != vulnerability
        for row in rows
    ):
        raise RuntimeError("Product Epic has no matching qualified occurrences")

    severity = next(
        (level for level in SEVERITIES
         if any(row["severity"] == level for row in rows)),
        "UNKNOWN",
    )
    score = max(row["score"] for row in rows)
    vectors = "; ".join(reported_vectors(rows)) or "Not provided"
    advisories = sorted({
        valid_url(row["evidence"]["advisory_href"])
        for row in rows if row["evidence"].get("advisory_href")
    })
    products = sorted({
        (row["product_display_name"], row["product_version"])
        for row in rows
    })
    nvd_url = (
        f"https://nvd.nist.gov/vuln/detail/{vulnerability}"
        if CVE_ID.fullmatch(vulnerability) else None
    )
    summary = [
        ["Vulnerability", vulnerability],
        ["Severity (highest reported)", severity],
        ["CVSS Score (maximum overallScore)", str(score)],
        ["CVSS Vector (reported)", vectors],
        ["NVD link", nvd_url or "Not available"],
    ]
    product_labels = [
        f"{name} / {version}" for name, version in products
    ]

    if description_format == "adf":
        content = [
            heading("Vulnerability overview"),
            adf_table(["Field", "Value"], summary),
        ]
        if nvd_url:
            content.append(linked_paragraph("NVD record", nvd_url))
        content.extend([
            heading("Affected parent product versions"),
            *[paragraph(value) for value in product_labels],
            heading("Black Duck advisories"),
            *[linked_paragraph(url, url) for url in advisories],
        ])
        if not advisories:
            content.append(paragraph("Not provided"))
        return {"type": "doc", "version": 1, "content": content}

    if description_format != "wiki":
        raise RuntimeError("Unsupported product description format")

    def wiki_row(values):
        return "|" + "|".join(wiki_text(value) for value in values) + "|"

    return "\n".join([
        "h2. Vulnerability overview",
        "||Field||Value||",
        *[wiki_row(values) for values in summary],
        *([wiki_link("NVD record", nvd_url)] if nvd_url else []),
        "",
        "h2. Affected parent product versions",
        *[f"* {wiki_text(value)}" for value in product_labels],
        "",
        "h2. Black Duck advisories",
        *([f"* {wiki_link('Black Duck advisory', url)}" for url in advisories]
          if advisories else ["Not provided"]),
    ])


def render_product_description(report, description_format):
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise RuntimeError("Unsupported structured product report")
    rows = report.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("Structured product report has no occurrences")

    first = rows[0]
    identity = (first["product_href"], first["vulnerability"])
    if any((row["product_href"], row["vulnerability"]) != identity for row in rows):
        raise RuntimeError("Product report mixes product/advisory identities")

    subprojects = sorted({
        (row["source_project"], row["source_version"])
        for row in rows if row["source_href"] != first["product_href"]
    })
    subproject_text = (
        "; ".join(f"{name} / {version}" for name, version in subprojects)
        or "None; qualifying findings are direct on the parent"
    )
    summary = [
        ["Product", first["product_display_name"]],
        ["Parent project", first["product"]],
        ["Parent version", first["product_version"]],
        ["Affected subproject versions", subproject_text],
        ["Phase", first["phase"]],
        ["Vulnerability", first["vulnerability"]],
        ["CVSS Score (maximum overallScore)", str(max(row["score"] for row in rows))],
        ["CVSS Vector (reported)", "; ".join(reported_vectors(rows)) or "Not provided"],
    ]
    evidence_rows = []
    references = [
        ("Product version", valid_url(first["product_href"])),
    ]
    for index, row in enumerate(rows, 1):
        evidence_rows.append([
            str(index),
            f"{row['source_project']} / {row['source_version']}",
            row["component"],
            row["component_version"],
            str(row["score"]),
            row["remediation_status"],
            row.get("exploit_source", "Not provided"),
        ])
        evidence = row["evidence"]
        for key, label in (
            ("occurrence_href", "Occurrence"),
            ("advisory_href", "Advisory"),
            ("origin_href", "Origin"),
        ):
            if evidence.get(key):
                references.append((
                    f"{row['component']} / {row['component_version']} — "
                    f"{row['source_project']} / {row['source_version']} — {label}",
                    valid_url(evidence[key]),
                ))

    people = first["people"]
    responsibilities = [
        f"{role}: {people['roles'].get(role, 'Not provided')}"
        for role in ROLES
    ]
    headers = [
        "#", "Source project/version", "Component", "Component version",
        "Overall Score", "Remediation", "Exploit evidence",
    ]

    if description_format == "adf":
        return {
            "type": "doc",
            "version": 1,
            "content": [
                heading("Affected parent product"),
                adf_table(["Field", "Value"], summary),
                heading("Affected components"),
                adf_table(headers, evidence_rows),
                heading("Product responsibilities"),
                paragraph(f"Metadata status: {people['status']}"),
                {
                    "type": "bulletList",
                    "content": [
                        {"type": "listItem", "content": [paragraph(value)]}
                        for value in responsibilities
                    ],
                },
                heading("Evidence references"),
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{
                                    "type": "text",
                                    "text": label,
                                    "marks": [{
                                        "type": "link",
                                        "attrs": {"href": url},
                                    }],
                                }],
                            }],
                        }
                        for label, url in references
                    ],
                },
            ],
        }

    if description_format != "wiki":
        raise RuntimeError("Unsupported product description format")

    def wiki_row(values):
        return "|" + "|".join(wiki_text(value) for value in values) + "|"

    return "\n".join([
        "h2. Affected parent product",
        "||Field||Value||",
        *[wiki_row(row) for row in summary],
        "",
        "h2. Affected components",
        "||" + "||".join(headers) + "||",
        *[wiki_row(row) for row in evidence_rows],
        "",
        "h2. Product responsibilities",
        f"Metadata status: {wiki_text(people['status'])}",
        *["* " + wiki_text(value) for value in responsibilities],
        "",
        "h2. Evidence references",
        *[f"* {wiki_link(label, url)}" for label, url in references],
    ])


def render_product_create_description(report, description_format):
    """Add the alert-compatible header only to a new Task's description."""
    rows = report.get("rows") if isinstance(report, dict) else None
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("Structured product report has no occurrences")
    first = rows[0]
    if any(
        row.get("product") != first.get("product")
        or row.get("product_version") != first.get("product_version")
        for row in rows
    ):
        raise RuntimeError("Product report mixes project/version names")

    ordinary = render_product_description(report, description_format)
    if description_format == "adf":
        return {
            **ordinary,
            "content": alert_adf_header(first) + ordinary["content"],
        }
    return "\n".join(alert_wiki_header(first)) + ordinary
