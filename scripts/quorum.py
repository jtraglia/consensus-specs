#!/usr/bin/env python3
"""
Quorum Bot - Requires approvals from N distinct teams before merging a PR.
"""

import os
import sys
import time
import requests

# Client team memberships are from:
# https://protocol-guild.readthedocs.io/en/latest/01-membership.html
TEAMS = {
    "lighthouse": [
        "antondlr",           # Anton Delaruelle
        "dapplion",           # dapplion
        "eserilev",           # Eitan Seri-Levi
        "jimmygchen",         # Jimmy Chen
        "jxs",                # João Oliveira
        "jking-aus",          # Josh King
        "macladson",          # Mac Ladson
        "ethDreamer",         # Mark Mackey
        "michaelsproul",      # Michael Sproul
        "pawanjay176",        # Pawan Dhananjay Ravi
        "realbigsean",        # Sean Anderson
    ],
    "lodestar": [
        "wemeetagain",        # Cayman Nava
        "matthewkeil",        # Matthew Keil
        "ensi321",            # NC
        "nazarhussain",       # Nazar Hussain
        "nflaig",             # Nico Flaig
        "philknows",          # Phil Ngo
        "twoeths",            # twoeths
    ],
    "nimbus": [
        "advaita-saha",       # Advaita Saha
        "agnxsh",             # Agnish Ghosh
        "jangko",             # Andri Lim
        "bhartnett",          # Ben Hartnett
        "tersec",             # Dustin Brody
        "etan-status",        # Etan Kissling
        "cheatfate",          # Eugene Kabanov
        "arnetheduck",        # Jacek Sieka
        "mjfh",               # Jordan Hrycaj
        "kdeme",              # Kim De Mey
    ],
    "prysm": [
        "Inspector-Butters",  # Bastin
        "ckarabats",          # Chris Karabats
        "james-prysm",        # James He
        "kasey",              # Kasey Kirkham
        "nalepae",            # Manu Nalepa
        "potuz",              # potuz
        "prestonvanloon",     # Preston Van Loon
        "rkapka",             # Radosław Kapka
        "terencechain",       # Terence Tsao
    ],
    "teku": [
        "zilm13",             # Dmitrii Shmatko
        "tbenr",              # Enrico Del Fante
        "gfukushima",         # Gabriel Fukushima
        "lucassaldanha",      # Lucas Saldanha
        "mehdi-aouadi",       # Mehdi Aouadi
        "rolfyone",           # Paul Harris
        "StefanBratanov",     # Stefan Bratanov
    ],
    "grandine": [
        "ArtiomTr",           # Artiom Tretjakovas
        "hangleang",          # Hangleang
        "povi",               # Povilas Liubauskas
        "sauliusgrigaitis",   # Saulius Grigaitis
        "tumas",              # Tumas
    ],
}

REQUIRED_APPROVALS = 4
COMMENT_MARKER = "<!-- quorum-bot -->"


class APIError(Exception):
    """API request failed (token-safe exception)."""
    pass


def api_request(method, url, token, **kwargs):
    """
    Make a GitHub API request without exposing the token in tracebacks.

    Catches request exceptions and re-raises as APIError with sanitized message.
    """
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    try:
        response = requests.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        if e.response is not None:
            raise APIError(f"{method} {url} failed: {e.response.status_code}") from None
        raise APIError(f"{method} {url} failed: connection error") from None


def build_user_to_team_map():
    """Build a reverse mapping from username to team name."""
    user_to_team = {}
    for team_name, members in TEAMS.items():
        for username in members:
            user_to_team[username.lower()] = team_name
    return user_to_team


def get_pr(repo, pr_number, token):
    """Fetch PR details."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    response = api_request("GET", url, token)
    return response.json()


def get_reviews(repo, pr_number, token):
    """Fetch all reviews for a PR."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    response = api_request("GET", url, token)
    return response.json()


def get_commit_status(repo, sha, token):
    """Get combined status check state for a commit."""
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/status"
    response = api_request("GET", url, token)
    return response.json()["state"]  # "success", "pending", "failure", "error"


def get_team_review_states(reviews, user_to_team):
    """
    Determine each team's review state based on the latest review from any team member.
    Reviews are processed in chronological order, so the last relevant review wins.
    Returns dict: team_name -> "APPROVED" | "CHANGES_REQUESTED"
    """
    team_states = {}
    for review in reviews:
        state = review["state"]
        if state in ("APPROVED", "CHANGES_REQUESTED"):
            username = review["user"]["login"].lower()
            team = user_to_team.get(username)
            if team:
                team_states[team] = state
    return team_states


def build_status_comment(team_states):
    """Build the status comment markdown."""
    lines = [
        COMMENT_MARKER,
        "## Quorum Bot",
        "",
        "This bot checks for approvals from consensus layer client teams. "
        "Each team's status reflects the most recent review from any of its members. "
        f"Once {REQUIRED_APPROVALS} teams have approved, this PR will be automatically merged.",
        "",
        "| Team | Status |",
        "|------|--------|",
    ]

    for team in TEAMS:
        state = team_states.get(team)
        if state == "APPROVED":
            status = "✅"
        elif state == "CHANGES_REQUESTED":
            status = "❌"
        else:
            status = "❓"
        lines.append(f"| {team.capitalize()} | {status} |")

    return "\n".join(lines)


def find_bot_comment(repo, pr_number, token):
    """Find existing bot comment on the PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    response = api_request("GET", url, token)
    for comment in response.json():
        if COMMENT_MARKER in comment["body"]:
            return comment["id"]
    return None


def post_or_update_comment(repo, pr_number, token, body):
    """Post a new comment or update existing one."""
    existing_id = find_bot_comment(repo, pr_number, token)

    if existing_id:
        url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}"
        response = api_request("PATCH", url, token, json={"body": body})
    else:
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        response = api_request("POST", url, token, json={"body": body})

    return response.json()


def merge_pr(repo, pr_number, token):
    """Squash merge the PR."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/merge"
    response = api_request("PUT", url, token, json={"merge_method": "squash"})
    return response.json()


def main():
    # Get environment variables
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr_number = os.environ.get("PR_NUMBER")

    if not all([token, repo, pr_number]):
        print("Missing required environment variables")
        print(f"  GITHUB_TOKEN: {'set' if token else 'missing'}")
        print(f"  GITHUB_REPOSITORY: {repo or 'missing'}")
        print(f"  PR_NUMBER: {pr_number or 'missing'}")
        sys.exit(1)

    user_to_team = build_user_to_team_map()

    print(f"Processing PR #{pr_number} in {repo}")
    print(f"Required approvals: {REQUIRED_APPROVALS} teams")

    # Fetch and process reviews
    reviews = get_reviews(repo, pr_number, token)
    team_states = get_team_review_states(reviews, user_to_team)

    approved_teams = [t for t, s in team_states.items() if s == "APPROVED"]
    print(f"Approving teams: {approved_teams}")

    # Post status comment
    comment_body = build_status_comment(team_states)
    post_or_update_comment(repo, pr_number, token, comment_body)
    print("Status comment updated")

    # Check if we have quorum
    if len(approved_teams) < REQUIRED_APPROVALS:
        print(
            f"Quorum not reached ({len(approved_teams)}/{REQUIRED_APPROVALS}). "
            f"Waiting for more approvals."
        )
        return

    print(f"Quorum reached ({len(approved_teams)}/{REQUIRED_APPROVALS})!")

    # Wait for status checks to pass (poll for up to 1 hour)
    pr = get_pr(repo, pr_number, token)
    head_sha = pr["head"]["sha"]

    max_attempts = 60  # 60 attempts * 60 seconds = 1 hour
    poll_interval = 60  # seconds

    for attempt in range(max_attempts):
        status = get_commit_status(repo, head_sha, token)
        print(f"Status checks: {status} (attempt {attempt + 1}/{max_attempts})")

        if status == "success":
            print("Merging...")
            merge_pr(repo, pr_number, token)
            print("PR merged successfully!")
            return
        elif status == "pending":
            print(f"Waiting {poll_interval}s for status checks...")
            time.sleep(poll_interval)
        else:
            print(f"Status checks failed ({status}). Not merging.")
            return

    print("Timed out waiting for status checks.")


if __name__ == "__main__":
    main()
