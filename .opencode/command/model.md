---
description: Show or configure the global AI model for all subsystems
---
Manage the global model configuration for $ARGUMENTS.
If no args: show current model config (main, fast, cheap, draft).
If "set <model-id>": set ALL subsystems to use the same model (e.g. /model set deepseek/deepseek-v4).
If "reset": reset to default role-based models.
This affects MoE routing and the model tiers (main/fast/cheap/draft) used across sub-agents. The choice is persisted to `.openhack/models.json`.
Environment: OPENHACK_MODEL, OPENHACK_FAST_MODEL, OPENHACK_CHEAP_MODEL
