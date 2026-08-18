---
name: overview
description: Overview of the delta fixture backend, shipped through a symlinked SKILL.md.
---

# Delta overview

Fixture skill for the cross-plugin unit-name resolution test. The real file
lives OUTSIDE the skill directory; `skills/overview/SKILL.md` is a relative
symlink up into this shared tree, which is how a plugin repo shares one text
between several skill variants.

Discovery accepts that link (it resolves in the plugin's own tree) and the
qualified copy is flat, so the copied link points somewhere else entirely.
Reading the leaf back out of that copy skipped the frontmatter rewrite -- and
the assertion behind it -- in silence, and shipped a `d-overview/` whose
SKILL.md the harness cannot read at all, still advertised by description in the
generated index.
