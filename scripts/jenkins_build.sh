#!/usr/bin/env bash
# Uso: scripts/jenkins_build.sh [AUDIT_MODE=true|false] [ZAP_SCAN=full|baseline]
# Dispara el pipeline y espera el resultado (usa credenciales de .env)
set -e; cd "$(dirname "$0")/.."; . ./.env
J=http://localhost:8088; A="admin:$JENKINS_ADMIN_PASSWORD"; C=$(mktemp)
CR=$(curl -s -c $C -u "$A" $J/crumbIssuer/api/json | python -c "import sys,json;d=json.load(sys.stdin);print(d['crumbRequestField']+':'+d['crumb'])")
N=$(curl -s -u "$A" "$J/job/securedev-pipeline/api/json?tree=nextBuildNumber" | python -c "import sys,json;print(json.load(sys.stdin)['nextBuildNumber'])")
curl -s -b $C -u "$A" -H "$CR" -X POST "$J/job/securedev-pipeline/buildWithParameters?AUDIT_MODE=${1:-false}&ZAP_SCAN=${2:-full}"
echo "Build #$N lanzado"
until curl -s -u "$A" "$J/job/securedev-pipeline/$N/api/json?tree=building" 2>/dev/null | grep -q '"building":false'; do sleep 5; done
curl -s -u "$A" "$J/job/securedev-pipeline/$N/api/json?tree=result,description"; echo
