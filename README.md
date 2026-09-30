# AI Security Range

A self-contained AI security demonstration lab. The app uses a real language model through Ollama or NVIDIA NIM. All company records, tools, target systems, security controls, logs, and reports run locally in this application.

## Start

```powershell
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --port 8765
```

Open http://127.0.0.1:8765.

For a local model, start Ollama separately and pull a model that supports tool calling, then enter its installed model name in the Playground. The default Ollama endpoint is `http://localhost:11434`; override it with `OLLAMA_URL`.

For NVIDIA NIM, open **Settings** in the app and save your API key once. The key is encrypted with Windows DPAPI for your Windows user account and persists across app restarts. Then select NVIDIA in the Playground and enter a model identifier available to your account. The saved key is never returned to the browser. You can remove it in Settings. Alternatively, set `NVIDIA_API_KEY` in the environment; on non-Windows systems, use this environment variable. The default endpoint is `https://integrate.api.nvidia.com/v1`; override it with `NVIDIA_BASE_URL`.

The Playground keeps separate model IDs for Ollama and NVIDIA. When you select NVIDIA, it loads IDs from the NVIDIA model catalog and suggests a chat model. Ollama names such as `qwen3:8b` cannot be used as NVIDIA model IDs; NVIDIA IDs look like `nvidia/nemotron-3-super-120b-a12b`. A model appearing in the catalog does not guarantee your account can invoke it. If NVIDIA still returns 404 for a listed model, check access to the chat endpoint in your NVIDIA account.

## What it does

- **Attack lab** runs the same scenario and attacker-controlled input with controls off and on. It shows side-by-side model responses, tool requests and results, guard decisions, deterministic evidence, and synthetic state changes. You can disable individual guardrails to see which layer matters.
- Playground with vulnerable and protected modes, custom prompts, role selection, and editable base system prompt.
- Five scenario categories across six scenarios: rogue agent, two privacy paths, fairness, toy cyber target, and high-risk response boundary.
- Real model tool calls against a per-run synthetic world. The protected mode checks role, data classification, and capabilities before execution, then scans output.
- Timeline of model requests, tool requests and results, policy decisions, and state changes.
- Local JSON Lines run history in `data/runs.jsonl` and a report calculated from completed runs.
- Paired fairness evaluation calls the selected model twice. Protected mode removes the irrelevant attribute before sending each profile.
- A **guided demonstration** at the top of Attack lab lets you choose one of six questions, inspect the expected sequence and evidence, and run a local check without a model. Its live comparison button uses the selected model and guardrails, then opens a three-step explanation, paired outcomes, key events, and expandable full traces.
  - **Tool-policy probes:** the rogue-agent, payroll, and toy-cyber cases submit a fixed synthetic tool request to the same guardrail engine used in a protected run. This shows each layer's allow or deny decision without implying that a model would make that request.
  - **Presidio:** focused email, phone, and demo-account recognizers return entity spans and anonymized text. `PRIV-002` shows the actual model-bound message before and after pre-model redaction. The preview itself makes no model call.
  - **Fairlearn:** a seeded synthetic cohort uses `MetricFrame` to show group selection rates and held-out accuracy before and after `ThresholdOptimizer` with a demographic-parity constraint. This cohort is separate from the two-call model consistency test.
  - **Behavior monitor:** every relevant event updates tool-request, denial, goal-drift, and sensitive-read counts. A threshold crossing creates a live `monitor_alert` trace event. You can change a threshold and recalculate alerts for the last protected run.
  - **CBRN boundary:** fixed safe and risky probes show the local pre-model rule's allow/block decisions. The risky probe contains no operational detail; the benign probe exposes overblocking.

The user interface shows an offline model state until a provider is available. It does not fabricate model responses or demonstration metrics. Each run gets a fresh copy of the synthetic world, so one experiment cannot contaminate another.

## Running an in-depth demonstration

1. Open **Attack lab**, pick a case card, and read the four-step path and **What counts as evidence?** guidance.
2. Click the case's **local control check**. This works without a model or API key and shows actual policy, Presidio, Fairlearn, or safety-filter output.
3. When a model is connected, click **Run live comparison**. Use **Continue to model comparison** if you want to edit the payload, model, or selected guardrails first.
4. Read **What happened in this pair** before interpreting the two outcomes. The result cards show key events; expand **Full execution trace** for all model and tool messages.
5. Use **Try one change next** to switch off a suggested guardrail, then rerun. Check whether another layer still blocks the same proposed action. In the rogue-agent case, the forged document requests a private file while the legitimate user asks only for a summary.

The toy cyber environment contains a deliberately exposed synthetic debug credential. The model must actually use the internal tools to log in and reach the restricted flag. The app never targets external systems.

A raw run that does not reach the objective cannot demonstrate that a defense prevented it. If a protected run avoids the objective without a denied action, that observation may reflect prompt hardening or ordinary model variability. The interface distinguishes this from a runtime guard that explicitly blocked a proposed action.

## API

`GET /api/health`, `GET /api/models/nvidia`, `GET /api/settings`, `PUT /api/settings/nvidia-key`, `DELETE /api/settings/nvidia-key`, `GET /api/scenarios`, `GET /api/scenarios/{scenario_id}/probe`, `GET /api/guardrails`, `POST /api/compare`, `POST /api/chat`, `POST /api/run-attack`, `POST /api/run-defense`, `POST /api/fairness`, `POST /api/privacy/preview`, `GET /api/fairness/demo`, `POST /api/monitor/evaluate`, `GET /api/safety/probes`, `GET /api/events`, `GET /api/evaluation`, `WS /api/events/live`. Key changes are restricted to requests from the same computer.

## Limits

The high-risk response label is a simple refusal heuristic and should be reviewed manually. Attack success is determined from known synthetic markers, tool results, and state changes, not an LLM judge. These metrics describe this contained lab and are not a certification of a model's broader security.

Presidio in this demo uses three focused patterns, not its full NLP recognizer catalog; it can miss other identifiers. Raw comparison runs and event history can contain the entered text, so use synthetic data only. Monitor thresholds are deterministic teaching defaults, not a trained anomaly baseline. Fairlearn's toy cohort shows a group-rate intervention on synthetic labels; it does not establish fairness of a real hiring decision. The CBRN filter is a narrow local rule, not a comprehensive safety system.
