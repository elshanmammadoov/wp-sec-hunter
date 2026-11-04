def repo_score(repo: dict) -> int:
    score = 0
    if repo.get("language", "").lower() == "php": score += 20
    stars = repo.get("stargazers_count", 0)
    if stars < 10: score += 10
    if stars < 3: score += 5
    if repo.get("fork", False): score -= 25
    if repo.get("archived", False): score -= 50
    if repo.get("has_issues"): score += 2
    text = f"{repo.get('name','')} {repo.get('description','')}".lower()
    for k in ("wordpress", "booking", "shop", "store", "school", "crm", "lms", "cms", "membership", "ajax", "api"):
        if k in text: score += 3
    return max(0, min(100, score))
