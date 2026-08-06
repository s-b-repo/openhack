## Signing a fresh ROE for `golecloud.co.za` from the shell

For your current engagement setup, this is the whole flow:

```bash
export OPENHACK_ROE_MCP_ALLOW_SIGN=1     # operator consent for this shell
# then, via the AI or by hand:
#   roe_create_draft
#   roe_set_targets    { "targets": ["golecloud.co.za", "*.golecloud.co.za"] }
#   roe_set_authorized_tools { "tools": ["nmap", "httpx", "nuclei", "ffuf"] }
#   roe_set_authorized_models { "models": ["deepseek/deepseek-v4", "anthropic/*"] }
#   roe_set_expiry_days { "days": 7 }
#   roe_sign_current
unset OPENHACK_ROE_MCP_ALLOW_SIGN         # lock signing again
```
