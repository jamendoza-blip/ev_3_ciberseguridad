# EV3 OCY1102 - Pipeline DevSecOps (SecureDev)

Pipeline CI/CD en Jenkins + Docker con controles de seguridad en cada etapa, remediación del código vulnerable
entregado, gestión de dependencias (Dependabot + pip-audit) y monitoreo de producción (Prometheus + Grafana).

## Levantar el entorno

```powershell
copy .env.example .env      # y cambiar las contraseñas
docker compose up -d --build
```

| Servicio   | URL                    |
|------------|------------------------|
| Jenkins    | http://localhost:8088  |
| Grafana    | http://localhost:3000  |
| Prometheus | http://localhost:9090  |
| App        | http://localhost:5000 (la despliega el pipeline) |

Jenkins vigila este repositorio (`pollSCM` cada 2 min): cada commit en `main` ejecuta el pipeline.
Lanzar manualmente: `bash scripts/jenkins_build.sh [AUDIT_MODE] [full|baseline]`.
Simular un incidente para Grafana: `python scripts/simular_incidente.py`.

## Etapas del pipeline (`Jenkinsfile`)

0 Trazabilidad · 1 Gitleaks · 2 pip-audit · 3 Bandit · 4 Build imagen · 5 pytest (10 pruebas de seguridad)
· 6 Trivy · 7 Deploy + smoke test · 8 OWASP ZAP. Cada etapa es una puerta de seguridad.

## Estructura

| Ruta | Contenido |
|------|-----------|
| `app/` | Aplicación Flask remediada, `init_db.py`, Dockerfile endurecido, requirements fijados |
| `tests/` | Pruebas de seguridad automatizadas |
| `infra/jenkins` | Imagen de Jenkins, plugins y Configuration as Code |
| `infra/prometheus`, `infra/grafana` | Scrape, datasource, dashboard y alertas provisionadas |
| `.github/dependabot.yml` | Actualizaciones automáticas de pip y Docker |
| `evidencias/` | Reportes del build #4 (vulnerable) y #6 (remediado), explotación manual, simulación de incidente |
| `entregado_por_docente/` | Archivos originales de la evaluación (referencia) |
