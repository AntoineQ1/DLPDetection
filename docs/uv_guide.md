# Python Environment Setup with `uv`

We use **`uv`** to manage the project's Python environment and dependencies.
It ensures that everyone on the team runs the exact same package versions (no matter the OS) and is particularly efficient.

## 1. Install `uv` (One-time setup)

On Linux:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

On Windows (via PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## 2. Quickstart (Install Dependencies)

From the project root, simply run:

```bash
uv sync
```

This automatically sets up a local `.venv/` directory and installs all locked dependencies from `uv.lock`.

## 3. Running Code and Tests

With `uv`, **you do not need to manually activate the virtual environment**. You just need to prepend your commands with `uv run`:

- **Run unit tests:**
```bash
uv run pytest
```

- **Run a script locally:**
```bash
uv run python detection/l7_web/luhn.py
```

*(It is also possible to manually activate the environment once created, with `source .venv/bin/activate`).*

## 4. Managing Dependencies

Do **not** edit dependencies manually in text files. Let `uv` handle them:

- **Add a package:**
```bash
uv add my_python_package_for_dd2391
```

- **Add a test/dev dependency:**
```bash
uv add --dev my_python_package_for_dd2391
```

- **Remove a package:**
```bash
uv remove my_python_package_for_dd2391
```

- **Update a specific package:**
```bash
uv lock --upgrade-package my_python_package_for_dd2391
```
Do **not** upgrade a package unless you are absolutely sure it won't break anything.

## 5. Git Conventions

- **Always commit:** `pyproject.toml` and `uv.lock`.
- **NEVER commit:** The `.venv/` folder (already excluded by the `.gitignore`).