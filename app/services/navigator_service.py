from app.services.heatmap_service import get_heatmap


def build_navigator_layer(db, country: str):

    heatmap = get_heatmap(db, country)

    techniques = []

    max_score = max([t["score"] for t in heatmap], default=1)

    for t in heatmap:

        # normalizar 0-100
        score = round((t["score"] / max_score) * 100, 2)

        techniques.append({
            "techniqueID": t["technique"],
            "score": score,
            "comment": f'{t["name"]} ({t["tactic"]})'
        })

    layer = {
        "name": f"Threat Landscape {country}",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": f"TTPs observed targeting {country}",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffcc", "#ffeda0", "#feb24c", "#f03b20"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "Low", "color": "#ffffcc"},
            {"label": "Medium", "color": "#feb24c"},
            {"label": "High", "color": "#f03b20"}
        ]
    }

    return layer

