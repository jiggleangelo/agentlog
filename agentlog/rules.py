def robots(catalog, selected, paths=None):
    paths = paths or ["/"]
    blocks = []
    for entry in catalog:
        if entry["id"] in selected and entry.get("robots_token"):
            blocks.append("\n".join([f"User-agent: {entry['robots_token']}"] + [f"Disallow: {path}" for path in paths]))
    return "\n\n".join(blocks)


def waf(catalog, snapshot, selected):
    clauses = []
    for entry in catalog:
        if entry["id"] not in selected: continue
        ranges = snapshot.get("agents", {}).get(entry["id"], {}).get("ranges", [])
        if not ranges: continue
        network_set = " ".join(ranges)
        for token in entry["ua_tokens"]:
            clauses.append(f'(http.user_agent contains "{token}" and not ip.src in {{{network_set}}})')
    expression = " or ".join(clauses)
    warning = "WARNING: expression may exceed provider limits.\n" if len(expression) > 3500 else ""
    return warning + expression


def nginx(catalog, selected):
    lines = ["# UA matching cannot verify IPs; use geo blocks for published ranges.", "map $http_user_agent $agentlog_block {", "    default 0;"]
    for entry in catalog:
        if entry["id"] in selected:
            for token in entry["ua_tokens"]: lines.append(f"    ~*{token} 1;")
    return "\n".join(lines + ["}"])
