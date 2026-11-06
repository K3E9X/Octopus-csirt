#!/usr/bin/env bash
# Install or upgrade Octopus CSIRT on a k3s cluster.
#
#   KUBE_CONTEXT=my-k3s IMAGE=registry.internal/octopus-csirt:v1 HOST=octopus.corp.example ./install.sh
#
# IT WILL NOT GUESS WHICH CLUSTER YOU MEANT. kubectl's current context is whatever you
# used last, and "whatever you used last" is how a manifest lands on production. The
# context is required, printed back, and confirmed before anything is applied.
#
# Safe to run twice. Secrets are created only when absent, and that is deliberate
# rather than tidy: regenerating the session secret signs everybody out, and
# regenerating the audit secret breaks the hash chain at the point of rotation, which
# the verifier will then report forever. Rotate those on purpose, not as a side effect
# of re-running an installer.
set -euo pipefail

NS="${NS:-octopus}"
IMAGE="${IMAGE:-}"
HOST="${HOST:-}"
PULL_POLICY="${PULL_POLICY:-IfNotPresent}"
REPLICAS="${REPLICAS:-2}"
CTX="${KUBE_CONTEXT:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf '\n  %s\n\n' "$*" >&2; exit 1; }

[ -n "$CTX" ]   || die "KUBE_CONTEXT is required. Available: $(kubectl config get-contexts -o name | tr '\n' ' ')"
[ -n "$IMAGE" ] || die "IMAGE is required, e.g. IMAGE=registry.internal/octopus-csirt:v1"
[ -n "$HOST" ]  || die "HOST is required, e.g. HOST=octopus.corp.example"
command -v kubectl >/dev/null || die "kubectl not found"
kubectl config get-contexts "$CTX" >/dev/null 2>&1 || die "no such context: $CTX"

K() { kubectl --context "$CTX" "$@"; }
SERVER="$(kubectl config view -o jsonpath="{.clusters[?(@.name=='$(kubectl config view -o jsonpath="{.contexts[?(@.name=='"$CTX"')].context.cluster}")')].cluster.server}" 2>/dev/null || echo '?')"

cat <<EOF

  context    $CTX
  server     $SERVER
  namespace  $NS
  image      $IMAGE   (pull: $PULL_POLICY)
  host       $HOST
  replicas   $REPLICAS

EOF
read -r -p "  Apply to this cluster? [y/N] " ok
[ "$ok" = "y" ] || [ "$ok" = "Y" ] || die "nothing applied"

K apply -f "$HERE/00-namespace.yaml"

# ---- secrets, created once ----------------------------------------------------------
gen() { openssl rand -base64 32 | tr -d '\n'; }

if K -n "$NS" get secret octopus-db >/dev/null 2>&1; then
  echo "  secret/octopus-db exists, left alone"
else
  K -n "$NS" create secret generic octopus-db \
    --from-literal=username=octopus \
    --from-literal=password="$(gen)"
fi

if K -n "$NS" get secret octopus-app >/dev/null 2>&1; then
  echo "  secret/octopus-app exists, left alone"
else
  # No LeakOSINT token here on purpose. An owner pastes it into /admin after the first
  # sign-in, where it is stored in the database and never appears in a manifest, in a
  # pod's environment, in the audit log, or in any response: the interface only ever
  # shows its last four characters.
  K -n "$NS" create secret generic octopus-app \
    --from-literal=sessionSecret="$(gen)" \
    --from-literal=auditSecret="$(gen)"
fi

# ---- database ------------------------------------------------------------------------
K apply -f "$HERE/10-postgres.yaml"
echo "  waiting for postgres"
K -n "$NS" rollout status statefulset/octopus-db --timeout=180s

# ---- application ----------------------------------------------------------------------
# The manifest carries working defaults so `kubectl apply -f 20-app.yaml` is valid on its
# own; this substitutes the two things that are site-specific and the one that depends on
# how the image got onto the node.
sed -e "s|ghcr.io/k3e9x/octopus-csirt:v1|$IMAGE|" \
    -e "s|imagePullPolicy: IfNotPresent|imagePullPolicy: $PULL_POLICY|" \
    -e "s|host: octopus.internal|host: $HOST|" \
    -e "s|- octopus.internal|- $HOST|" \
    -e "s|  #       - octopus.internal|  #       - $HOST|" \
    -e "s|^  replicas: 2$|  replicas: $REPLICAS|" \
    "$HERE/20-app.yaml" | K apply -f -

K apply -f "$HERE/30-networkpolicy.yaml"

echo "  waiting for the application"
K -n "$NS" rollout status deploy/octopus-csirt --timeout=240s

cat <<EOF

  Installed.

  1. Open  https://$HOST  and REGISTER FIRST. The first account claims the deployment
     and becomes the owner, once, atomically. Everybody after that is a hunter with no
     balance, which is the gate on an internally reachable sign-up form: an account
     nobody has funded cannot run a single query.

  2. Paste the LeakOSINT token in /admin. Nothing searches until it is there, and the
     tool says so rather than returning empty reports.

  3. Grant credits per person in /admin.

  Check it:
    kubectl --context $CTX -n $NS get pods
    curl -s https://$HOST/api/health?deep=1

  The network policy is only enforced if this cluster runs a policy controller. k3s
  bundles one unless it was started with --disable-network-policy. Verify rather than
  assume:
    kubectl --context $CTX run probe --rm -it --image=alpine --restart=Never -- \\
      sh -c 'nc -zv -w3 octopus-db.$NS.svc.cluster.local 5432'
    # from the default namespace this must FAIL

EOF
