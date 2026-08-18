# Deploying the control plane

Plain `kubectl` and hand-written YAML.

> Verified on kind (`kind v0.32.0`, Kubernetes v1.36.1, Colima) on 2026-08-18: rollout
> succeeded, pod ran non-root with a read-only root filesystem and zero restarts, the
> Service routed, the mounted bundle was served, and a check-in appeared in the fleet view. No Helm — templating hides the objects, and the
objects are the thing worth understanding first.

```bash
kubectl apply -f k8s/namespace.yaml
kubectl -n toolgate create secret generic toolgate-bundle --from-file=bundle.json=./bundle.json
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/configmap.yaml -f k8s/deployment.yaml -f k8s/service.yaml
kubectl -n toolgate rollout status deploy/toolgate-control
kubectl -n toolgate port-forward svc/toolgate-control 8090:80
```

## What each object is doing, and why

**A note on what you will see first.** The shipped ConfigMap has an empty OIDC issuer and
no static callers, so the control plane refuses every request with a 401 until you point it
at an identity provider. That is not a broken deployment — it is a service that has not been
told who may talk to it, failing closed. `/actuator/health` still answers, which is how you
tell the difference.

**Namespace** — a blast radius and a place to hang quotas and NetworkPolicies later.
`kubectl delete ns toolgate` removes the whole experiment, which is the property you want
while learning.

**Secret, not ConfigMap, for the bundle.** The bundle is signed, so this is not about
integrity — nobody forges policy by editing it. It is about confidentiality: the bundle
describes exactly which tools are reachable and which need a human, and that is a useful
thing to read before deciding what to attack. Note that a Kubernetes Secret is only
base64-encoded at rest unless the cluster has encryption-at-rest configured; it is a
*category* marker as much as a protection.

**The signing key is not here at all.** Bundles are signed wherever they are produced — a
release pipeline, someone's laptop with a hardware key. A control plane that can sign policy
is a control plane whose compromise rewrites policy. It only serves bytes it cannot forge.

**Deployment, `replicas: 3`, `RollingUpdate` with `maxUnavailable: 0`.** This was
`replicas: 1` and `Recreate` until fleet state moved into Postgres, and the reason is worth
keeping: with the registry in memory, two pods behind one Service each received a fraction
of the check-ins, so the coverage report returned a different answer depending on which pod
answered — reporting machines as unmonitored when they were not.

`maxUnavailable: 0` with `maxSurge: 1` means a deploy adds a pod, waits for it to pass
readiness, then retires an old one. It costs one pod's worth of extra capacity during the
rollout and buys a deploy with no reduction in service.

**Postgres** (`k8s/postgres.yaml`) is a Deployment with `Recreate` and a `ReadWriteOnce`
PVC — a rolling update would try to start a second pod while the first still holds the
volume, and the new one would sit `Pending` with a `FailedAttachVolume` event. That RWO
constraint is exactly why StatefulSets exist: they give each replica its own volume and a
stable identity, which is what you need the moment you want more than one database pod.
One is enough here, and pretending otherwise would be theatre.

Its readiness probe runs `pg_isready` rather than checking the port, because Postgres
accepts connections while it is still recovering — a TCP check reports ready too early and
the first queries fail.

**Probes.** These are worth getting right rather than copying:

- `readinessProbe` → `/actuator/health/readiness`. Controls whether the Service sends
  traffic here. Failing it takes the pod out of rotation without killing it.
- `livenessProbe` → `/actuator/health/liveness`. Controls whether the kubelet *kills* the
  container. It must not check dependencies. A liveness probe that fails when a downstream
  is unavailable turns someone else's outage into a restart loop that makes it worse.
- Deliberately **not** using `/actuator/health` for liveness, even though it is the
  interesting endpoint. It reports DOWN when policy is stale — which is exactly the state
  you want to *see*, not the state you want the kubelet to respond to by killing the
  process and losing the fleet registry.
- `startupProbe` gives the JVM time to boot without a slow start being read as a crash.

**`resources`.** `requests` is what the scheduler reserves and what it uses to pick a node;
`limits` is what the kernel enforces. Exceeding a memory limit is not throttled — the
process is OOM-killed, which surfaces as exit code 137 (128 + 9, SIGKILL) and
`CrashLoopBackOff`. CPU is throttled rather than killed, so a tight CPU limit shows up as
mysterious latency instead of a crash.

**`securityContext`.** Non-root, read-only root filesystem, all capabilities dropped. A
service whose job is confining what agents can reach has no business running as root inside
its own container. The read-only filesystem needs an `emptyDir` at `/tmp`, because the JVM
writes there.

**`terminationGracePeriodSeconds` and `preStop`.** On delete, Kubernetes sends SIGTERM and
removes the pod from Service endpoints — but those two happen concurrently, so a request can
arrive after shutdown has begun. The `preStop` sleep lets endpoint removal propagate before
the process starts refusing. Spring Boot's graceful shutdown then drains in-flight requests.
Ignoring SIGTERM is how you get exit code 143 in the logs and dropped requests during every
deploy.

## Things deliberately left out

- **Ingress** — `port-forward` is enough on kind, and ingress is roadmap stage 3.
- **HPA** — pointless at `replicas: 1`, and scaling needs the state moved out first.
- **NetworkPolicy** — stage 5, and kind's default CNI does not enforce them anyway.
- **Helm** — stage 5. Feel the objects first.

## The exercise this sets up

Move the fleet registry into Postgres, then raise `replicas` and switch to `RollingUpdate`.
That is the roadmap's "an app plus a Postgres dependency", except the app is real: you can
break it in ways that matter and see the coverage report go wrong.
