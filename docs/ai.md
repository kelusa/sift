# AI Integration

Sift can analyze audit findings using a local or remote LLM. It sends the top findings as context and returns actionable recommendations.

## Setup

### Local LLM (default)

Start the bundled Ollama container:

```bash
docker compose up -d
```

This runs [phi3:3.8b](https://hub.docker.com/r/mdelapenya/phi3) on port 11434.

Verify it's running:

```bash
curl http://localhost:11434/v1/models
```

### Custom endpoint

Create `~/.sift/ai.json`:

```json
{
  "endpoint": "http://localhost:11434/api/chat",
  "model": "phi3:3.8b"
}
```

You can point this to any OpenAI-compatible chat API (Ollama, vLLM, Bedrock, OpenAI, etc.).

## Usage

```bash
# Analyze all latest findings (security + cost)
sift ai --account dev

# Scope to a module
sift ai --account dev --module security
sift ai --account dev --module cost

# Scope to a service
sift ai --account dev --service ec2

# Custom question
sift ai --account dev "What is the most urgent issue to fix?"

# Analyze a specific finding by ID
sift ai --finding a3b2c1d4e5f6a7b8
```

| Flag | Description |
|------|-------------|
| `--module` | Scope to security or cost findings |
| `--service` | Scope to a specific AWS service |
| `--finding` | Analyze a specific finding by ID |
| `--question` | Custom question (alternative to positional arg) |

## How it works

1. Queries the SQLite history database for findings
2. Filters to non-PASS findings, sorted by risk (CRITICAL first)
3. Caps at top 10 findings per module to fit context window
4. Sends a compact summary to the LLM with your question
5. Returns the LLM's analysis

## Context format

The LLM receives findings in this format:

```
## SECURITY findings (top 10 issues):
- [CRITICAL] sqs/public_access: queue policy allows wildcard principal (my-queue)
- [HIGH] ebs/no_encryption: volume not encrypted (vol-abc123)
...
```

## Model recommendations

| Model | Speed | Quality | Notes |
|-------|-------|---------|-------|
| phi3:3.8b | Slow (CPU) | Basic | Default, runs locally without GPU |
| llama3:8b | Moderate | Good | Better reasoning, needs more RAM |
| GPT-4 / Claude | Fast (API) | Excellent | Requires API key, not local |

For production use, point `~/.sift/ai.json` to a hosted API for faster responses and better analysis quality.

## Limitations

- Local phi3:3.8b on CPU can take 2-5 minutes to respond
- Small models may hallucinate or give generic advice
- Context is limited to top 10 findings per module — large environments may miss lower-priority issues
- No streaming output yet (waits for full response)
