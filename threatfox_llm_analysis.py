from openai import OpenAI
import json
from datetime import datetime, timedelta

# ==================================================
# 1️/ CONNEXION À OPENROUTER
# ==================================================

client = OpenAI(
    api_key="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",  
    base_url="https://openrouter.ai/api/v1"
)

MODEL_NAME = "mistralai/mistral-7b-instruct"

# ==================================================
# 2️/ PARAMÈTRES TEMPORELS
# ==================================================

CURRENT_DATE = datetime(2026, 1, 29)
OBSOLETE_DELTA = timedelta(days=180)  # 6 mois

# ==================================================
# 3️/ CHARGEMENT DES DONNÉES THREATFOX
# ==================================================

with open("threatfox_data.json", "r", encoding="utf-8") as f:
    threatfox_data = json.load(f)

enriched_results = {}

# Compteurs statistiques
total_iocs = 0
obsolete_iocs = 0

# ==================================================
# 4️/ ANALYSE DE CHAQUE IOC
# ==================================================

for report_id, iocs in threatfox_data.items():
    enriched_results[report_id] = []

    for ioc in iocs:
        total_iocs += 1

        prompt = f"""
Tu es un analyste expert en Cyber Threat Intelligence.

 Date actuelle : 2026-01-29

RÈGLES OBLIGATOIRES :
- Si last_seen est NULL → IOC obsolète
- Si last_seen date de plus de 6 mois → IOC obsolète
- Un malware actif ne signifie PAS que l’IOC est encore valide
- Analyse uniquement la temporalité

IOC : {ioc['ioc_value']}
Type : {ioc['ioc_type']}
Malware : {ioc['malware_printable']}
Threat type : {ioc['threat_type']}
First seen : {ioc['first_seen_utc']}
Last seen : {ioc['last_seen_utc']}
Confidence source : {ioc['confidence_level']} %

Retourne STRICTEMENT ce JSON valide :

{{
  "statut": "actif | inactif",
  "fraicheur": "récente | ancienne",
  "obsolescence": "faible | moyenne | élevée",
  "priorite": "faible | moyenne | élevée",
  "justification": "courte explication"
}}
"""

        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=400
            )

            raw = response.choices[0].message.content.strip()
            start = raw.find("{")
            end = raw.rfind("}") + 1
            llm_result = json.loads(raw[start:end])

        except Exception as e:
            llm_result = {
                "statut": "inactif",
                "fraicheur": "ancienne",
                "obsolescence": "élevée",
                "priorite": "faible",
                "justification": f"Erreur LLM : {str(e)}"
            }

        # ==================================================
        # 5️/ RÈGLES DE SÉCURITÉ TEMPORELLES (FAILSAFE)
        # ==================================================

        last_seen = ioc.get("last_seen_utc")

        if last_seen is None:
            llm_result.update({
                "statut": "inactif",
                "fraicheur": "ancienne",
                "obsolescence": "élevée",
                "priorite": "faible",
                "justification": "IOC jamais reconfirmé (last_seen nul)"
            })
        else:
            last_seen_dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            if CURRENT_DATE - last_seen_dt > OBSOLETE_DELTA:
                llm_result.update({
                    "statut": "inactif",
                    "fraicheur": "ancienne",
                    "obsolescence": "élevée",
                    "priorite": "faible",
                    "justification": "IOC ancien (> 6 mois)"
                })

        # ==================================================
        # 6️/ STATISTIQUES
        # ==================================================

        if llm_result["obsolescence"] == "élevée":
            obsolete_iocs += 1

        # Enrichissement final
        enriched_ioc = ioc.copy()
        enriched_ioc["llm_temporal_analysis"] = llm_result
        enriched_results[report_id].append(enriched_ioc)

        print(" IOC analysé :", ioc["ioc_value"])

# ==================================================
# 7️/ CALCUL POURCENTAGE IOC OBSOLÈTES
# ==================================================

if total_iocs > 0:
    obsolete_percentage = (obsolete_iocs / total_iocs) * 100
else:
    obsolete_percentage = 0

print("\n STATISTIQUES GLOBALES")
print(f"Total IOC analysés : {total_iocs}")
print(f"IOC obsolètes : {obsolete_iocs}")
print(f"Pourcentage d’IOC obsolètes : {obsolete_percentage:.2f} %")

# ==================================================
# 8️/ SAUVEGARDE DES RÉSULTATS
# ==================================================

with open("threatfox_enriched.json", "w", encoding="utf-8") as f:
    json.dump(enriched_results, f, indent=2, ensure_ascii=False)

stats = {
    "total_iocs": total_iocs,
    "obsolete_iocs": obsolete_iocs,
    "obsolete_percentage": round(obsolete_percentage, 2)
}

with open("cti_statistics.json", "w", encoding="utf-8") as f:
    json.dump(stats, f, indent=2, ensure_ascii=False)

print("\n Analyse terminée")
print(" Fichiers générés :")
print("- threatfox_enriched.json")
print("- cti_statistics.json")
