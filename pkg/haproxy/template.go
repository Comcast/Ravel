package haproxy

var haproxyConfig string = `
# Autogenerated by Ravel. Do not change.


global
    log 127.0.0.1        local0
    log 127.0.0.1        local1 notice
    user                 haproxy
    group                haproxy

defaults
    timeout connect 5s
    timeout client 5s
    timeout server 5s
    log                     global
    mode                    tcp
    option                  dontlognull

{{ range $templ := . }}
listen listen6-{{ $templ.ServicePort }}
        bind	{{ $templ.Source }}:{{ $templ.ServicePort }} {{if .MTU}} mss {{ .MTU }} {{ end }}
        mode    tcp
        {{ range $i, $ip := $templ.DestIPs }}server  {{ $ip }}-{{ $templ.TargetPort }}    {{ $ip }}:{{  $templ.TargetPort  }}
        {{ end }}
{{ end }}
`
