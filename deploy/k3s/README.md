# Running Octopus CSIRT on k3s

Four manifests, one image, two secrets. The secrets are **not** in this repository and
there is no example file to copy, because an example secret is a real secret the first
time somebody forgets to change it.

## 1. Secrets

Generated on your machine, applied directly, never committed.

```sh
kubectl apply -f deploy/k3s/00-namespace.yaml

# database credentials, in one place, read by both the database and the app
kubectl -n octopus create secret generic octopus-db \
  --from-literal=username=octopus \
  --from-literal=password="$(openssl rand -base64 30)"

# session signing and the audit chain key
kubectl -n octopus create secret generic octopus-app \
  --from-literal=sessionSecret="$(openssl rand -base64 32)" \
  --from-literal=auditSecret="$(openssl rand -base64 32)"
```

Two things about those keys.

**Rotating `sessionSecret` signs everybody out.** That is the correct behaviour and the
reason to do it deliberately rather than in a hurry.

**Rotating `auditSecret` breaks the audit chain at the point of rotation**, and the
verifier will say so. That is also correct: the chain proves nothing if the key that
signs it can be swapped silently. Rotate it when you mean to, and record when.

The LeakOSINT token is optional here. Either add it to `octopus-app` as
`leakosintToken`, or leave it out and have the owner paste it into `/admin` after the
first sign-in, which keeps it out of the manifest and out of every pod's environment.

## 2. The image

The repository builds to a standalone Next bundle, so the image is small and runs with
`node server.js`.

```sh
docker build -t ghcr.io/k3e9x/octopus-csirt:v1 .
docker push ghcr.io/k3e9x/octopus-csirt:v1
```

Pin a real tag or a digest. `:latest` makes a rollback impossible to describe and a
rollout impossible to repeat.

If the registry is private, give the namespace a pull secret and reference it from the
Deployment:

```sh
kubectl -n octopus create secret docker-registry ghcr \
  --docker-server=ghcr.io --docker-username=USER --docker-password=TOKEN
```

## 3. Apply

```sh
kubectl apply -f deploy/k3s/10-postgres.yaml
kubectl apply -f deploy/k3s/20-app.yaml        # edit the host and the image first
kubectl apply -f deploy/k3s/30-networkpolicy.yaml

kubectl -n octopus rollout status deploy/octopus-csirt
kubectl -n octopus get pods,svc,ingress
```

No migration step. The application creates its own tables on first use and the
statements are all `IF NOT EXISTS`, so a restart is cheap and a rollback does not leave
a half-built schema.

## 4. The first account

The first registration **claims the deployment**: it becomes the `owner`, atomically,
once. Everybody who registers after that is a `hunter` with **no balance**, which is the
gate on an internally reachable sign-up form: an account nobody has funded cannot run a
single query. Grant credit per person from `/admin`.

So register yourself first, before telling the team the URL.

## 5. Checking it

```sh
# liveness: is this process serving
curl -s https://octopus.internal/api/health

# deeper: is the database reachable, is a source token present (503 when it is not)
curl -s https://octopus.internal/api/health?deep=1
```

The liveness probe deliberately does **not** check the database. A probe that fails
during a database outage restarts a pod that still cannot reach the database, turning an
outage into a crash loop that also takes down the part that was still working.

Verify the network policy rather than assuming it. k3s bundles kube-router's policy
controller and enforces these by default, but a cluster started with
`--disable-network-policy`, or running a replacement CNI, accepts the object and
enforces nothing:

```sh
kubectl run probe --rm -it --image=alpine --restart=Never -- \
  sh -c 'nc -zv -w3 octopus-db.octopus.svc.cluster.local 5432'
# from the default namespace this must FAIL
```

## 6. Backups

`local-path` is k3s's default StorageClass, which means **the volume lives on one node**
and is not a backup. If that node dies, so does the case history.

```sh
kubectl -n octopus exec octopus-db-0 -- \
  pg_dump -U octopus -d octopus --format=custom > octopus-$(date +%F).dump
```

Cases hold personal data: pinned breach data about identifiable people. A dump is the
same data in a file that leaves the cluster. Encrypt it, put it where incident evidence
is already kept, and give it the retention the rest of your incident records have.

## What is in each file

| File | What it does |
| --- | --- |
| `00-namespace.yaml` | One namespace, so the whole thing can be quota'd, audited and deleted as one object. |
| `10-postgres.yaml` | Postgres as a **StatefulSet**, not a Deployment: a Deployment with a PVC will run two pods against one volume during a rolling update, and two postgres processes on one data directory destroy a database rather than restart it. |
| `20-app.yaml` | Deployment (2 replicas, non-root, read-only root filesystem), Service, Traefik Ingress. |
| `30-networkpolicy.yaml` | The database accepts the app and nothing else; the app accepts the ingress controller and nothing else. |

## Scaling

Two replicas is right. Sessions are signed cookies rather than server state, so any pod
can serve any request, and there is nothing to make sticky.

The one thing that does **not** scale with replicas is the upstream rate limit. The
LeakOSINT client serialises requests inside a process, so two pods make two queues and
can push twice the rate at the index. With a handful of analysts that is not a problem.
If it becomes one, the fix is a shared limiter and not more replicas.
