# Deploy the recorded-evidence viewer

The root entry point is `streamlit_app.py`. This public viewer reads committed results, request records, topology, policy and the demo GIF. It does not import the CLI, start Docker, contact Batfish, execute network changes or require Anthropic credentials.

## Local preview

```bash
python3.12 -m venv .venv-ui
.venv-ui/bin/python -m pip install -r requirements.txt
.venv-ui/bin/python -m streamlit run streamlit_app.py
```

The viewer's dependencies are separate from the full lab dependencies in `pyproject.toml`. `requirements.txt` pins the two directly imported third-party packages to the versions used for local AppTest validation. Installation from the public package registry and actual Community Cloud deployment have not been performed by this change.

## Community Cloud settings

After committing and pushing the new files, open https://share.streamlit.io/ and choose Create app:

| Setting | Value |
| --- | --- |
| Repository | `fauzan111/AI-network-change-assistant-with-pre-deployment-verification` |
| Branch | `main` |
| Main file path | `streamlit_app.py` |
| Python version in Advanced settings | `3.12` |
| Secrets | None required |

Keep the root `requirements.txt`, `docs/eval/summary_template.json`, all three `docs/eval/template_*.jsonl` files, `network/topology.yml`, `network/invariants.yml` and optionally `docs/media/demo.gif` in the repository. Existing evaluation/network assets are already tracked in the local repository. Community Cloud selects root `requirements.txt` ahead of `pyproject.toml` when no higher-priority dependency file exists. Avoid adding a `uv.lock` for unrelated lab dependencies without checking deployment dependency selection.

This is a recorded-evidence deployment. Live requests, Batfish verification and Containerlab execution remain in the existing CLI/lab environment. The historical `llm-only` evaluation filename represents the no-checks configuration with the reference compiler; the UI labels it accordingly and does not imply Claude generated those evaluated changes.

Official guidance: https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy and https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies.
