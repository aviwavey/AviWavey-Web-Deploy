# AVI Wavey Website — Deployment Mirror

This repository contains the approved, compiled public release of the AVI Wavey website.

## Repository roles

- **Private development source:** `AVI-Wavey/PublicInterface`
- **Public release mirror:** `aviwavey/AviWavey-Web-Deploy`
- **Production website:** [aviwavey.com](https://www.aviwavey.com)

Development, reviews, and source-code changes belong in the private organization repository. This repository is intentionally limited to deployable browser assets and minimal hosting configuration.

## Release traceability

Each release includes `deployment-manifest.json`, which records the exact organization source commit used to produce the exported website.

Current source commit:

`5a40229664710f1882a2cdcf8f8da2edea5cf661`

## Security boundary

This repository does not contain the original TypeScript/React source tree, development dependencies, Git history from the organization repository, environment files, credentials, or private organization documentation.

The compiled JavaScript, CSS, fonts, images, and HTML are public website assets and are expected to be downloadable by website visitors.

## Updating the website

1. Complete and review changes in `AVI-Wavey/PublicInterface`.
2. Produce and verify the compiled `dist` output.
3. Scan the output for accidentally embedded credentials or private material.
4. Replace the release files in this repository.
5. Update `deployment-manifest.json` with the approved source commit.
6. Verify the Vercel preview before promoting or changing the production domain.

Do not develop directly in this repository.
