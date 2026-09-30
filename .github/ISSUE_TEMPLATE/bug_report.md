---
name: Bug Report
about: Report a broken evaluation, incorrect risk score, or API issue
title: "[BUG] "
labels: bug
assignees: UtkarshOver9000
---

## Describe the bug
<!-- A clear description of the problem -->

## To Reproduce
Include the login event payload that triggered the issue:
```json
{
  "user_id": "...",
  "login_ts": "...",
  "lat": ...,
  "lon": ...,
  "device_id": "...",
  "ip": "..."
}
```

## Expected behavior
<!-- What did you expect Aegis to return? -->

## Actual Response
<!-- Paste the actual JSON response here -->

## Environment
- Python version:
- Deployment target: [ ] Vercel  [ ] Docker  [ ] Local uvicorn
