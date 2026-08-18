# Per-instance NixOS extensions

Each instance owns a tiny flake at `~/.config/cogbox/instances/<name>/flake/flake.nix`. Whatever NixOS module you put in it is folded into that instance's guest at the next start: extra packages, mounts, systemd services, env vars -- the full NixOS module system. This is the manual, single-instance form of extensibility; for installable, versioned extensions see [plugins](plugins.md), which build on the same mechanism.

## How it works

When the instance flake differs from the scaffolded default, the wrapper re-execs itself via `nix run --override-input userExtensions path:<instance-config-dir>/flake`, rebuilding the microvm runner with the user's `nixosModules.default` included. An unedited scaffold matches the built-in default byte-for-byte and the re-exec is skipped, so a default install boots without any extra `nix` evaluation.

The flake lives in its own subdirectory so unrelated edits to sibling files (`config.json`, `authorized_keys`) don't bust the flake's source hash and force a rebuild.

The scaffold written on first init exposes a no-op `nixosModules.default`:

```nix
{
    description = "cogbox per-instance extensions";

    outputs = { self }: {
        nixosModules.default = { pkgs, lib, ... }: {
            # Add per-instance packages and modules here.
        };
    };
}
```

## Which nixpkgs `pkgs` is

`pkgs` in the module resolves to cogbox's nixpkgs -- the wrapper passes `--override-input userExtensions/nixpkgs`, so any input literally named `nixpkgs` you declare is replaced by cogbox's. To use a *different* nixpkgs in one instance, declare a separately-named input (e.g. `nixpkgs-custom`) and reference it explicitly in the module.

## Example: pre-populate the nix store with build deps

A bare `nix shell nixpkgs#hbase` inside the VM refetches HBase on every boot, because the guest's writable nix store overlay is a tmpfs. Land HBase in the system closure instead, so it's registered in the guest's nix DB at boot and resolves locally:

```nix
# ~/.config/cogbox/instances/hbase/flake/flake.nix
{
    outputs = { self }: {
        nixosModules.default = { pkgs, ... }: {
            environment.systemPackages = with pkgs; [ hbase openjdk21 maven ];
            system.extraDependencies  = with pkgs; [ hbase openjdk21 maven ];
        };
    };
}
```

`environment.systemPackages` puts the binaries on PATH inside the VM; `system.extraDependencies` ensures the build-time inputs are also part of the closure, so `nix develop nixpkgs#hbase` (or any other workflow that realises those deps) finds them already realised.

The wrapper rebuilds the microvm runner with this module included on the next launch. Subsequent launches reuse the cached build until you edit the flake.

## Notes

- The first time `nix run` evaluates a per-instance `path:` flake, it writes a `flake.lock` next to the user's `flake.nix` (inside the `flake/` subdir). This is normal.
- The mechanism re-execs once per launch (guarded internally so the loop ends after one hop). Non-launch verbs (`list`, `status`, `stop`, `rules`, `ssh`) never re-exec; neither does an unedited scaffold.
- The first launch *with* a customized flake fetches and caches every cogbox flake input (microvm.nix, nix-mcp, etc.) -- it needs network access on that one launch. Subsequent launches reuse the cache.
- When the instance has [plugins](plugins.md) installed, the user flake is not overridden in directly; it becomes the `user` input of the generated plugin-composition flake, which imports the plugin modules and your module together (yours last). Manual flake edits and plugins compose.
- `microvm.extraArgsScript` is reserved for Cogbox's launch-only host-directory support. Defining it in an extension conflicts at Nix evaluation rather than silently replacing the dynamic-directory hook. Put extension-owned static QEMU arguments in `microvm.qemu.extraArgs`.
