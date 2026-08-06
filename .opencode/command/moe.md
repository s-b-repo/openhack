---
description: Show MoE (Mixture of Experts) routing for a prompt
---
Show the Mixture of Experts routing for $ARGUMENTS.
If no args: show all 12 expert neurons with usage counts, target agents, and models.
If "route <prompt>": test-route a prompt to see which expert handles it.
Each expert specializes in one domain (port scanning, web exploit, AD, binary RE, cloud, etc.) and routes to the optimal agent type.
MoE uses the global model config — set with /model.
