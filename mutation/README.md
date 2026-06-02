# Mutation testing

Tooling for running mutation testing on the security-critical contracts using
[Certora Gambit](https://github.com/Certora/gambit).

## Files

- `gambit_conf.json` — Gambit configuration. Lists the contracts to mutate and
  the mutation operators to apply. Paths inside this file are resolved relative
  to this directory (Gambit's rule), which is why entries use `../contracts/…`
  and `sourceroot: ".."`.
- `run-campaign.sh` — driver script. Generates mutants, then for each mutant
  swaps it into the source tree, runs `forge test`, observes whether tests
  catch the change (killed) or not (survived), and restores the original.

## Running

From the repo root:

```bash
npm run mutation                            # full campaign
bash mutation/run-campaign.sh --generate-only   # generate mutants without testing
bash mutation/run-campaign.sh --resume          # resume after interrupt
```

A full campaign over the contracts listed in `gambit_conf.json` produces
~300–700 mutants and takes 30–90 minutes. Run `bash mutation/run-campaign.sh -h`
for the full flag/env reference.

## Output (gitignored)

- `gambit_out/` — generated mutants (one subdirectory per mutant)
- `mutation-report.tsv` — per-mutant result log

Both live at the repo root, not under `mutation/`, because the script invokes
Gambit from the repo root.
