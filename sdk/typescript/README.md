# secure-code — TypeScript SDK

`skillslib` is a thin TypeScript loader and validator for the SKILL.md
format used by **secure-code**. (The published npm package name remains
`@skills-library/skillslib` for backwards compatibility.)

## Install

```bash
npm install @skills-library/skillslib
```

## Quick start

```ts
import { loadSkill, loadAll, validate, extract } from "@skills-library/skillslib";

const skill = loadSkill("skills/secret-detection/SKILL.md");
const errors = validate(skill);
if (errors.length) throw new Error(errors.join("\n"));

console.log(extract(skill, "compact"));

const all = loadAll("skills");
console.log(`loaded ${all.length} skills`);
```

## API

- `loadSkill(path: string): Skill`
- `loadAll(dir: string): Skill[]`
- `validate(skill: Skill): string[]`
- `extract(skill: Skill, tier: "minimal" | "compact" | "full"): string`

## License

MIT — same as the parent repository. Copyright (c) 2024-2026
[ShieldNet360](https://www.shieldnet360.com).
