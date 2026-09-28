from __future__ import annotations

import re
from urllib.parse import urlsplit


ROLES = ("maintainer", "owner", "supporter", "securitymanager")


def plain(value):
    return "" if value is None else str(value)


def paragraph(value):
    value = plain(value)
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": value}] if value else [],
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

    summary = [
        ["Product", first["product_display_name"]],
        ["Black Duck project", first["product"]],
        ["Version", first["product_version"]],
        ["Phase", first["phase"]],
        ["Vulnerability", first["vulnerability"]],
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
                heading("Affected product"),
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
        "h2. Affected product",
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
        *[
            f"* [{wiki_text(label)}|"
            + url.replace("[", "%5B").replace("]", "%5D").replace("|", "%7C")
            + "]"
            for label, url in references
        ],
    ])
