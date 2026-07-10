# surx-verify (GitHub Action)

Fail your pipeline if a dataset was tampered with.

```yaml
- uses: Christ10-8/surx-verify-action@v1
  with:
    path: data/trainset.surx
    pubkey: keys/data-team.pub
```

Exit 0 = signature valid and every entry intact. Exit 1 = the log shows exactly which entry changed.

> To publish on the Marketplace this folder must live in its own repository
> (`Christ10-8/surx-verify-action`) with a `v1` tag — see LAUNCH_COMMANDS.
