from collections import defaultdict
from app.services.risk_score import calculate_risk
from app import models


def risk_to_color(score: float):

    # Escala CTI
    if score >= 80:
        return "#ff0000"  # crítico
    elif score >= 60:
        return "#ff5c00"
    elif score >= 40:
        return "#ff9900"
    elif score >= 20:
        return "#ffd000"
    elif score >= 10:
        return "#fff200"
    else:
        return "#e8ffe8"


def build_matrix(db, country: str):

    top_risks = calculate_risk(db, country)

    matrix = defaultdict(list)

    for item in top_risks:

        tech = db.query(models.Technique).filter_by(tech_id=item["technique"]).first()

        if not tech:
            continue

        tactic = tech.tactic or "unknown"

        matrix[tactic].append({
            "technique": tech.tech_id,
            "name": tech.name,
            "risk": item["risk"],
            "color": risk_to_color(item["risk"])
        })

    return dict(matrix)

