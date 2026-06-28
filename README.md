# PromptGuard 2.0

Multi-agent prompt injection defense system built for the **Regolo Hackathon 2026** (AI & Security).

PromptGuard runs a 5-agent pipeline — Detection, Technique Classification, RAG Poisoning, Explainer, and Mitigation — to analyze prompts, score risk (0–100), and return a verdict: **SAFE**, **SUSPICIOUS**, **DANGEROUS**, or **BLOCK**.

## Features

- **Live Threat Scan** — paste any prompt and watch all agents analyze it
- **Attack Simulator** — compare an unprotected bot vs. a PromptGuard-protected bot
- **Attack Library** — whaling, jailbreaks, RAG poisoning, delimiter escapes, and more
- **Deep Scan** — full multi-agent report powered by the Regolo API
- **Interactive demo site** — client-side dashboard with live charts at [amber-bodhi-jaxc.here.now](https://amber-bodhi-jaxc.here.now/)

## Requirements

- Python 3.10+
- A [Regolo](https://regolo.ai) API key

## Setup

```bash
git clone https://github.com/Sam9875/hackathon-Cyber-security-.git
cd hackathon-Cyber-security-

pip install -r requirements.txt
```

Copy the example env file and add your credentials:

```bash
cp .env.example .env
```

Edit `.env`:

```env
REGOLO_API_KEY=your_regolo_api_key_here
REGOLO_MODEL=gpt-oss-120b
REGOLO_BASE_URL=https://api.regolo.ai/v1
```

## Run

```bash
python -m streamlit run app.py
```

Open the URL shown in the terminal (usually `http://localhost:8501`).

## Project structure

| File / folder      | Description                                      |
|--------------------|--------------------------------------------------|
| `app.py`           | Streamlit UI (simulator, deep scan, attack lib)  |
| `agents.py`        | Individual agent prompts and logic               |
| `orchestrator.py`  | Pipeline orchestration and report building       |
| `examples.py`      | Attack library payloads and presets              |
| `config.py`        | API config, verdict thresholds, colors           |
| `site/index.html`  | Standalone interactive demo dashboard            |

## Architecture

```
User Prompt
    │
    ▼
Orchestrator ──► Detection Agent
              ├──► Technique Classifier
              ├──► RAG Poisoning Agent
              ├──► Explainer Agent
              └──► Mitigation Agent
    │
    ▼
Final Report: risk score 0–100 + verdict
```

## License

Hackathon project — use and adapt as needed.