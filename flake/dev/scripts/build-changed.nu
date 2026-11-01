#!/usr/bin/env -S nix shell nixpkgs#nushell --command nu

use std/log
use lib/common.nu *

def main [
  subcommand: string, # Either "eval" or "build"
  --base_ref: string = "HEAD", # Git ref to compare against; can be a branch, tag, or commit hash
  --dry, # If set, will only print the targets that would be built, without actually building them
  --minimal, # Build only one target per changed file, even if multiple hosts/homes reference it; This will always select the first host/home in alphabeltical order
  --optimised, # Not implemented; exits with an error
  ...nix_args # Additional arguments to pass to `nix build`
] {
  let repo_root = goto_repo_root $base_ref
  let changes = get_changes $base_ref
  let modules = get_modules $repo_root

  if $optimised {
    fail "--optimised is not implemented"
  }

  run_standard $subcommand $changes $modules $minimal $dry $nix_args $repo_root

  close
}

def close [
  msg?: string,
  --code: int = 0
] {
  if $msg != null {
    if $code == 0 {
      log info $"Info: ($msg)"
    } else {
      log error $"Error: ($msg)"
    }
  }

  cd -
  exit $code
}

def goto_repo_root [base_ref: string] {
  let repo_root = (git rev-parse --show-toplevel | str trim)
  if ($repo_root == "") { close --code 2 "unable to determine repository root (git rev-parse failed)" }
  cd $repo_root
  log info $"Base ref: ($base_ref)"
  log info "Gathering changed files..."

  $repo_root
}

def get_changes [base_ref: string] {
  mut changed_files = []
  $changed_files ++= (git ls-files --others --exclude-standard e> /dev/null | lines)
  $changed_files ++= (git diff --name-only $base_ref e> /dev/null | lines)
  if ($changed_files | length) == 0 { close "No changed files found. Nothing to build." }

  log info "Changed files:"
  for f in $changed_files { log info $"\t($f)" }

  $changed_files
}

def get_modules [repo_root: string] {
  let modules = ($repo_root | path join "flake/dev/scripts/module-graph.nu") e> /dev/null | from json
  $modules
}

# Standard mode:
# - consider all changed files
# - for each host/home, evaluate all options
def run_standard [
  subcommand: string,
  changed_files: list,
  modules: table,
  minimal: bool,
  dry: bool,
  nix_args: list,
  repo_root: string
] {
  mut targets = []
  for file in $changed_files {
    let possible_modules = $modules | where { $in.file == $file }
    let m = if ($possible_modules | length) > 0 {
      $possible_modules | first
    } else {
      log debug $"File '($file)' did not map to any host/home in module graph; skipping."
      continue
    }

    if ($m.hosts | length) > 0 {
      mut hosts = $m.hosts
      if $minimal { $hosts = [ ($m.hosts | first) ] }
      for host in $hosts {
        let target = $".#nixosConfigurations.($host).config.system.build.toplevel"
        $targets ++= [$target]
        log info $"[($file)] -> [($target)]"
      }
    } else if ($m.homes | length) > 0 {
      mut homes = $m.homes
      if $minimal { $homes = [ ($m.homes | first) ] }

      for home in $homes {
        let target = $".#homeConfigurations.($home).activationPackage"
        $targets ++= [$target]
        log info $"[($file)] -> [($target)]"
      }
    } else {
      log debug $"File '($file)' has no hosts or homes referencing it; skipping."
    }
  }

  $targets = ($targets | uniq)
  if ($targets | length) == 0 {
    close "No nix targets determined from changed files."
  }

  log info "Selected nix build targets:"
  for t in $targets { log info $"  ($t)" }

  if $dry {
    close "Dry-run enabled; not executing nix build."
  }

  let command_args = [
    (if $subcommand == "build" { "--no-link" })
    "--print-build-logs"
    "--override-input"
    "devenv-root"
    ($"file+file://($repo_root)/.devenv/root")
    ...$nix_args
  ] | where { $in != null }
  log info $"Nix Command Args: ($command_args | str join ' ')"
  for t in $targets {
    log info $"Building target: ($t)"
    nix $subcommand $t ...$command_args
  }
}

