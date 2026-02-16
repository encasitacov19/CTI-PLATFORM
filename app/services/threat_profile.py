from collections import Counter

# reglas simples pero muy poderosas
PROFILE_RULES = {
    "RANSOMWARE": [
        "impact",
        "lateral-movement",
        "credential-access",
        "defense-evasion"
    ],
    "ESPIONAGE": [
        "collection",
        "exfiltration",
        "command-and-control"
    ],
    "INITIAL_ACCESS_BROKER": [
        "initial-access",
        "credential-access"
    ],
    "BOTNET": [
        "command-and-control",
        "persistence"
    ]
}


def build_country_profile(matrix):

    tactic_counter = Counter()

    for tactic, techniques in matrix.items():
        tactic_counter[tactic] += len(techniques)

    scores = {}

    for profile, required_tactics in PROFILE_RULES.items():
        score = 0
        for t in required_tactics:
            score += tactic_counter.get(t, 0)
        scores[profile] = score

    ordered = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    return {
        "dominant_activity": ordered[0][0],
        "scores": scores,
        "tactics_observed": dict(tactic_counter)
    }

