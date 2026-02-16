from collections import defaultdict

# secuencias típicas de operación (kill chain realista)
TACTIC_FLOW = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact"
]


def predict_next_tactics(matrix):

    observed = set(matrix.keys())

    highest_index = -1

    for tactic in observed:
        if tactic in TACTIC_FLOW:
            idx = TACTIC_FLOW.index(tactic)
            highest_index = max(highest_index, idx)

    # siguiente fase probable
    if highest_index + 1 < len(TACTIC_FLOW):
        return TACTIC_FLOW[highest_index + 1]

    return None


def predict_next_techniques(db, matrix):

    next_tactic = predict_next_tactics(matrix)

    if not next_tactic:
        return {"prediction": None, "techniques": []}

    from app import models

    techniques = db.query(models.Technique)\
        .filter(models.Technique.tactic == next_tactic)\
        .limit(10)\
        .all()

    return {
        "prediction": next_tactic,
        "techniques": [t.tech_id for t in techniques]
    }

