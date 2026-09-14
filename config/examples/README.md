# Configuration Examples

Copy these files to `~/.sift/` and customize as needed.

| File | Purpose | Required |
|------|---------|----------|
| `tagging.json` | Tag compliance policy for `sift aws governance --check tagging` | Yes (for governance) |
| `ai.json` | LLM endpoint, model, and prompt templates | No (has defaults) |
| `prices.json` | Custom pricing overrides | No (uses embedded eu-west-1 prices) |
| `remediations.json` | Custom remediation templates | No (uses embedded templates) |

## Notes

- `prices.json`: Only include fields you want to override. See `audit/pricing/prices.json` for the full format with all supported services.
- `remediations.json`: Only include entries you want to override. See `audit/remediation/remediations.json` for all templates.
- `ai.json`: If not present, defaults to local Ollama at `localhost:11434` with `phi3:3.8b`.
- `tagging.json`: Required for `sift aws governance`. Errors if missing.
