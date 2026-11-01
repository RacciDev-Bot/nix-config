use std/log

# Log an error and exit with status 1.
export def fail [message: string] {
  log error $message
  exit 1
}

# Return the certificate directory for a service on a server host.
export def service-cert-dir [
  output: path # Repository root
  host: string # Server host name
  service: string # Service directory under the host
] {
  $output | path join "hosts" "server" $host $service
}
