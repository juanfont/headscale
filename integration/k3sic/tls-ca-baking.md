# Running the operator against a private-CA TLS Headscale

`TestK8sOperator` points the Tailscale Kubernetes operator at an **HTTP**
Headscale (`hsic.WithoutTLS`, `loginServer = http://<ip>:<port>`). That keeps
the harness small: the operator and proxy pods need no CA, so there is no image
baking, no containerd import, and no CoreDNS hostname mapping.

This note records how to run the same test against a **TLS** Headscale serving a
private CA, in case a future test needs to exercise realistic TLS. It is not
wired up; reconstruct it from here.

## Why it is involved

tailscaled/tsnet verify the control connection against Go's
`x509.SystemCertPool` (on the Alpine images: `/etc/ssl/certs/ca-certificates.crt`).
A private CA must therefore be in the pod's **system trust store**.

As of the tailscale operator chart on `main`, there is no supported way to hand
a CA _file_ to a proxy pod:

- `ProxyClass.spec.statefulSet.pod` has no `volumes`.
- `ProxyClass...tailscaleContainer` has no `volumeMounts`, and its `env` is a
  reduced schema (`name`/`value` only — no `valueFrom`/`envFrom`).
- `operatorConfig` exposes `extraEnv` but no `extraVolumes`.

`SSL_CERT_FILE`/`SSL_CERT_DIR` _are_ honoured by tailscaled, but they need a
file that cannot be projected in. So the CA has to be baked into the images.

## The recipe

1. Serve Headscale with TLS (the `hsic` default) and grab `headscale.GetCert()`.
   Pass it to the cluster so in-container `helm`/`kubectl` trust it.

2. Bake the CA into derived operator and proxy images. For each of
   `tailscale/k8s-operator:<tag>` and `tailscale/tailscale:<tag>`, build:

   ```Dockerfile
   FROM <base>
   COPY headscale-ca.crt /usr/local/share/ca-certificates/headscale-ca.crt
   RUN update-ca-certificates
   ```

   Build on the host docker daemon (it has egress to pull the base images),
   `ExportImage` the result to a docker-format tarball, stream it into the k3s
   container, and import it into the kubelet's containerd namespace:

   ```
   ctr --namespace k8s.io images import <tarball>
   ```

   Tag the derived images `headscale.local/...:<tag>-ca` and run them with
   `imagePullPolicy: Never` (the `headscale.local/` prefix is never resolved by
   a registry).

3. Wire the derived images into the chart via `operatorConfig.image` /
   `proxyConfig.image`. The operator's proxy StatefulSet template hard-codes
   `imagePullPolicy: Always`, so a `ProxyClass` must override the proxy image
   **and** set `imagePullPolicy: Never`; Connectors must reference that
   ProxyClass explicitly (`defaultProxyClass` does not apply to them).

4. Pods resolve Headscale through CoreDNS, not the container's `/etc/hosts`, and
   the cert's only SAN is the Headscale hostname (dialing by IP fails TLS
   verification). Install a `coredns-custom` ConfigMap mapping the hostname to
   the Headscale IP and gate on the `kube-dns` Service having ready endpoints
   before starting the operator.

The full implementation lived in `integration/k3sic/k3sic.go` and
`integration/k8s_operator_test.go` before the switch to HTTP; recover it from
git history (`PrepareTailscaleImages`, `bakeAndImportImage`, `caBuildContext`,
`ConfigureCoreDNSHost`) if needed.
