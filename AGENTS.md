# AGENTS.md

## Project overview

This is a small Python CTI monitoring application:

- `dashboard.py` is the Streamlit UI. It owns navigation, asset CRUD, settings UI, filtering, pagination, and charts.
- `main.py` is the collection pipeline. It reads monitoring settings and assets, calls external CTI APIs, normalizes findings, and stores alerts.
- `storage.py` owns the SQLite schema and alert persistence in `darkweb_monitoring.db`.
- `sync_assets.py` synchronizes asset lists from `app_settings.json` into `monitored_assets.json`.
- `app_settings.json` and `monitored_assets.json` are runtime data/configuration files. Preserve their existing structure when changing code.

## Running the application

Run commands from the repository root because file paths are relative:

```powershell
python -m streamlit run dashboard.py
python main.py
python sync_assets.py
```

The dashboard and collector share JSON files and the SQLite database. Do not run destructive data migrations or rewrite those files as part of an unrelated change.

## Dependencies and environment

The application uses Python packages including `streamlit`, `pandas`, `plotly`, `requests`, `python-dotenv`, and SQLite from the standard library. Install project dependencies in the active virtual environment before running the app. Some integrations use environment variables loaded from `.env`, notably `OTX_API_KEY`; never commit secrets.

## Testing and validation

The `test_*.py` files are executable network smoke-test scripts, not a conventional isolated unit-test suite. Run only the relevant script when checking an external integration, for example:

```powershell
python test_crtsh.py
python test_otx.py
python test_phishtank.py
python test_ransomware.py
```

These tests require network access and may depend on API availability or credentials. For UI changes, validate by starting Streamlit and exercising the affected workflow in the browser. For pure Python changes, first use the narrowest relevant script or compile check, such as `python -m py_compile dashboard.py`.

## Coding conventions

- Keep user-facing labels and existing behavior consistent with the current French/English mixed UI.
- Prefer small changes in the module that owns the behavior; avoid duplicating storage or synchronization logic.
- Preserve the existing JSON keys and asset types (`Domaine`, `Adresse IP`, `Email`, `Mot-clé`).
- Use UTF-8 when reading or writing JSON. Keep external API calls bounded with timeouts and handle request failures without crashing the collection loop.
- Be careful when importing `dashboard.py`: Streamlit page setup and rendering happen at module import time, so it is not a normal library module.
- Do not add real credentials, generated databases, or transient runtime uploads to source control.
