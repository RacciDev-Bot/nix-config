use std/log

# Abort with an error.
#
# Raises instead of exiting so callers can clean up in `catch` blocks.
export def fail [message: string] {
  error make { msg: $message }
}

# Configure `std/log` output for a helper command.
export def --env setup-logging [
  --verbose
  --json
] {
  log set-level (if $json { 61 } else if $verbose { 10 } else { 20 })
  $env.NU_LOG_FORMAT = "%ANSI_START%%LEVEL%|%MSG%%ANSI_STOP%"
}

# Return the certificate directory for a service on a server host.
export def service-cert-dir [
  output: path # Repository root
  host: string # Server host name
  service: string # Service directory under the host
] {
  $output | path join "hosts" "server" $host $service
}
